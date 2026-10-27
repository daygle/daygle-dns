<script>
  import IconButton from '../IconButton.svelte';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';
  import ColumnPicker from '../ColumnPicker.svelte';
  import { isHidden } from '../columns.svelte.js';

  const LEASE_COLUMNS = [
    { key: 'address', label: 'Address', locked: true },
    { key: 'name', label: 'Name' },
    { key: 'device', label: 'Device' },
    { key: 'scope', label: 'Scope' },
    { key: 'state', label: 'State' },
    { key: 'expires', label: 'Expires' },
  ];
  const showL = (key) => !isHidden('dhcp-leases', key);

  // Viewers are read-only (the server refuses their changes).
  const isAdmin = getStoredUser()?.role !== 'viewer';

  const TABS = [
    {
      id: 'leases',
      label: 'Leases',
      tagline: 'The addresses handed out to devices on your networks, and the names they are known by.',
    },
    {
      id: 'v4',
      label: 'IPv4 Scopes',
      tagline: 'The IPv4 networks addresses are handed out on, with their range, gateway and DNS settings.',
    },
    {
      id: 'v6',
      label: 'IPv6 Scopes',
      tagline: 'The IPv6 networks served by DHCPv6: addresses for devices that ask, or DNS settings only.',
    },
    {
      id: 'settings',
      label: 'Settings',
      tagline: 'Turn the DHCP server on, and choose the zone devices are registered in.',
    },
  ];

  let tab = $state('leases');
  const current = $derived(TABS.find((t) => t.id === tab));

  let settings = $state(null); // the saved [dhcp] section
  let status = $state(null);
  let interfaces = $state([]);
  let leases = $state([]);
  let zones = $state([]);
  let error = $state(null);
  let notice = $state(null);
  let saving = $state(false);
  let edit = $state(null); // { kind: 'v4' | 'v6', index, form }
  let form = $state(null); // the Settings tab's form copy

  const DEFAULTS = { enabled: false, scopes: [], scopes_v6: [], dns_zone: '' };

  async function load() {
    error = null;
    try {
      const cfg = await api.config();
      settings = { ...DEFAULTS, ...(cfg.dhcp || {}) };
      form = { enabled: settings.enabled, dns_zone: settings.dns_zone };
      await loadStatus();
      try {
        zones = (await api.zones()).map((z) => z.name).filter((n) => !n.endsWith('.arpa') || n === 'home.arpa');
      } catch {
        zones = [];
      }
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function loadStatus() {
    try {
      const data = await api.dhcp();
      status = data.status;
      interfaces = data.interfaces || [];
      leases = data.leases || [];
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function save(next, message) {
    saving = true;
    error = null;
    notice = null;
    try {
      await api.updateSettings({ dhcp: next });
      settings = next;
      form = { enabled: next.enabled, dns_zone: next.dns_zone };
      notice = message;
      edit = null;
      await loadStatus();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  // Scopes ------------------------------------------------------------------

  function lines(text) {
    return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  }

  function list(text) {
    return text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
  }

  function reservationsText(rs) {
    return (rs || []).map((r) => [r.client, r.address, r.hostname].filter(Boolean).join(', ')).join('\n');
  }

  function parseReservations(text) {
    return lines(text).map((l) => {
      const [client = '', address = '', hostname = ''] = l.split(/[,\s]+/);
      return { client, address, hostname, description: '' };
    });
  }

  function startEdit(kind, index) {
    error = null;
    notice = null;
    if (kind === 'v4') {
      const s = index === null ? null : settings.scopes[index];
      edit = {
        kind,
        index,
        form: {
          name: s?.name || '',
          enabled: s ? s.enabled !== false : true,
          interface: s?.interface || '',
          subnet: s?.subnet || '',
          range_start: s?.range_start || '',
          range_end: s?.range_end || '',
          router: s?.router || '',
          dns_servers: (s?.dns_servers || []).join(', '),
          domain_name: s?.domain_name || '',
          ntp_servers: (s?.ntp_servers || []).join(', '),
          lease_hours: (s?.lease_secs || 86400) / 3600,
          reservations: reservationsText(s?.reservations),
          options: (s?.options || []).map((o) => `${o.code} ${o.value}`).join('\n'),
        },
      };
    } else {
      const s = index === null ? null : settings.scopes_v6[index];
      edit = {
        kind,
        index,
        form: {
          name: s?.name || '',
          enabled: s ? s.enabled !== false : true,
          interface: s?.interface || '',
          prefix: s?.prefix || '',
          stateless: s ? !s.range_start && !s.range_end : false,
          range_start: s?.range_start || '',
          range_end: s?.range_end || '',
          dns_servers: (s?.dns_servers || []).join(', '),
          domain_search: (s?.domain_search || []).join(', '),
          valid_hours: (s?.valid_secs || 86400) / 3600,
          preferred_hours: (s?.preferred_secs || 43200) / 3600,
          reservations: reservationsText(s?.reservations),
        },
      };
    }
  }

  function closeEdit() {
    if (!saving) edit = null;
  }

  function saveScope() {
    const f = edit.form;
    let scope;
    if (edit.kind === 'v4') {
      scope = {
        name: f.name.trim(),
        enabled: f.enabled,
        interface: f.interface.trim(),
        subnet: f.subnet.trim(),
        range_start: f.range_start.trim(),
        range_end: f.range_end.trim(),
        router: f.router.trim(),
        dns_servers: list(f.dns_servers),
        domain_name: f.domain_name.trim(),
        ntp_servers: list(f.ntp_servers),
        lease_secs: Math.round(Number(f.lease_hours) * 3600) || 86400,
        reservations: parseReservations(f.reservations),
        options: lines(f.options).map((l) => {
          const [code, ...rest] = l.split(/\s+/);
          return { code: Number(code), value: rest.join(' ') };
        }),
      };
    } else {
      scope = {
        name: f.name.trim(),
        enabled: f.enabled,
        interface: f.interface.trim(),
        prefix: f.prefix.trim(),
        range_start: f.stateless ? '' : f.range_start.trim(),
        range_end: f.stateless ? '' : f.range_end.trim(),
        dns_servers: list(f.dns_servers),
        domain_search: list(f.domain_search),
        valid_secs: Math.round(Number(f.valid_hours) * 3600) || 86400,
        preferred_secs: Math.round(Number(f.preferred_hours) * 3600) || 43200,
        reservations: parseReservations(f.reservations),
      };
    }
    const key = edit.kind === 'v4' ? 'scopes' : 'scopes_v6';
    const scopes = [...settings[key]];
    if (edit.index === null) scopes.push(scope);
    else scopes[edit.index] = scope;
    save({ ...settings, [key]: scopes }, edit.index === null ? `Scope "${scope.name}" added.` : `Scope "${scope.name}" saved.`);
  }

  function removeScope(kind, index) {
    const key = kind === 'v4' ? 'scopes' : 'scopes_v6';
    const name = settings[key][index].name;
    if (!confirm(`Delete scope "${name}"? Its leases stay until they expire.`)) return;
    save({ ...settings, [key]: settings[key].filter((_, i) => i !== index) }, `Scope "${name}" deleted.`);
  }

  // Leases ------------------------------------------------------------------

  function isV6(lease) {
    return lease.address.includes(':');
  }

  function scopeOf(lease) {
    const key = isV6(lease) ? 'scopes_v6' : 'scopes';
    return (settings?.[key] || []).findIndex((s) => s.name === lease.scope);
  }

  function reserved(lease) {
    const i = scopeOf(lease);
    if (i < 0 || !lease.hw_address) return false;
    const scope = settings[isV6(lease) ? 'scopes_v6' : 'scopes'][i];
    const norm = (t) => t.toLowerCase().replace(/[:.-]/g, '');
    return (scope.reservations || []).some((r) => norm(r.client) === norm(lease.hw_address));
  }

  function reserve(lease) {
    const key = isV6(lease) ? 'scopes_v6' : 'scopes';
    const i = scopeOf(lease);
    const scopes = [...settings[key]];
    const scope = { ...scopes[i] };
    scope.reservations = [
      ...(scope.reservations || []),
      { client: lease.hw_address, address: lease.address, hostname: lease.hostname, description: '' },
    ];
    scopes[i] = scope;
    save({ ...settings, [key]: scopes }, `${lease.address} is now reserved for this device.`);
  }

  async function removeLease(lease) {
    if (!confirm(`Forget the lease on ${lease.address}? The device keeps the address until it next renews, and may then be given another.`)) return;
    error = null;
    notice = null;
    try {
      await api.deleteDhcpLease(lease.address);
      notice = `Lease on ${lease.address} removed.`;
      await loadStatus();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function expires(lease) {
    return formatDateTime(new Date(lease.expires * 1000).toISOString());
  }

  const STATES = { bound: 'Active', offered: 'Offered', released: 'Released', declined: 'In Use Elsewhere' };

  // Settings ----------------------------------------------------------------

  function saveSettings() {
    save(
      { ...settings, enabled: form.enabled, dns_zone: form.dns_zone.trim() },
      form.enabled ? 'DHCP settings saved.' : 'DHCP settings saved. The server is off.',
    );
  }

  function ifaceAddresses(i) {
    return i.addresses.filter((a) => !a.startsWith('fe80')).join(', ');
  }

  $effect(() => {
    load();
  });
</script>

<PageHeader icon={icons.dhcp} title="DHCP" tagline={current.tagline} />

<div class="tabs">
  {#each TABS as t (t.id)}
    <button class="tab" class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
  {/each}
</div>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error && !edit}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if !settings}
  {#if !error}<div class="card"><p class="muted">Loading...</p></div>{/if}
{:else}
  {#if !settings.enabled && tab !== 'settings'}
    <div class="card" style="margin-bottom: 14px">
      <p class="muted" style="margin: 0">
        The DHCP server is off. Add a scope, then turn it on under the Settings tab.
      </p>
    </div>
  {/if}

  {#if tab === 'leases'}
    <div class="card">
      <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
        <h3 style="margin: 0">Leases ({leases.length})</h3>
        <div class="row" style="gap: 8px">
          <button class="secondary" onclick={loadStatus}>Reload</button>
          <ColumnPicker table="dhcp-leases" columns={LEASE_COLUMNS} />
        </div>
      </div>
      {#if leases.length === 0}
        <p class="muted">No leases yet.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Address</th>
                {#if showL('name')}<th>Name</th>{/if}
                {#if showL('device')}<th>Device</th>{/if}
                {#if showL('scope')}<th>Scope</th>{/if}
                {#if showL('state')}<th>State</th>{/if}
                {#if showL('expires')}<th>Expires</th>{/if}
                {#if isAdmin}<th class="num">Actions</th>{/if}
              </tr>
            </thead>
            <tbody>
              {#each leases as l (l.address)}
                <tr class:disabled={l.state !== 'bound'}>
                  <td><code>{l.address}</code></td>
                  {#if showL('name')}
                    <td>
                      {l.hostname || '-'}
                      {#if l.dns_name}<div class="muted small"><code>{l.dns_name}</code></div>{/if}
                    </td>
                  {/if}
                  {#if showL('device')}<td><code class="small" title={isV6(l) ? 'DUID' : 'MAC address'}>{l.hw_address || '-'}</code></td>{/if}
                  {#if showL('scope')}<td class="muted">{l.scope}</td>{/if}
                  {#if showL('state')}
                    <td>
                      <span class="pill" class:ok={l.state === 'bound'}>{STATES[l.state] || l.state}</span>
                      {#if reserved(l)}<span class="pill">Reserved</span>{/if}
                    </td>
                  {/if}
                  {#if showL('expires')}<td class="muted nowrap">{expires(l)}</td>{/if}
                  {#if isAdmin}
                    <td class="num">
                      <div class="row" style="gap: 6px; justify-content: flex-end">
                        {#if l.state === 'bound' && l.hw_address && scopeOf(l) >= 0 && !reserved(l)}
                          <IconButton icon="pin" label="Reserve: always give this device this address" onclick={() => reserve(l)} disabled={saving} />
                        {/if}
                        <IconButton icon="delete" variant="danger" label="Remove lease {l.address}" onclick={() => removeLease(l)} />
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
        Active leases with a device name are registered in DNS when a zone is
        chosen under Settings. Reserve keeps the device on its current
        address. Removing a lease frees the address and its DNS names.
      </p>
    </div>
  {:else if tab === 'v4' || tab === 'v6'}
    {@const key = tab === 'v4' ? 'scopes' : 'scopes_v6'}
    <div class="card">
      <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
        <h3 style="margin: 0">{tab === 'v4' ? 'IPv4' : 'IPv6'} Scopes ({settings[key].length})</h3>
        {#if isAdmin}<button onclick={() => startEdit(tab, null)}>Add Scope</button>{/if}
      </div>
      {#if settings[key].length === 0}
        <p class="muted">No scopes yet.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scope</th><th>Network</th><th>Addresses</th><th>Interface</th><th class="num">Reservations</th><th class="num">Active</th>
                {#if isAdmin}<th class="num">Actions</th>{/if}
              </tr>
            </thead>
            <tbody>
              {#each settings[key] as s, i (s.name)}
                <tr class:disabled={s.enabled === false}>
                  <td><strong>{s.name}</strong>{#if s.enabled === false}<span class="pill">Disabled</span>{/if}</td>
                  <td><code>{tab === 'v4' ? s.subnet : s.prefix}</code></td>
                  <td class="muted">{s.range_start ? `${s.range_start} - ${s.range_end}` : 'DNS settings only'}</td>
                  <td class="muted">{s.interface || 'Any with an address in it'}</td>
                  <td class="num">{(s.reservations || []).length}</td>
                  <td class="num">{leases.filter((l) => l.scope === s.name && l.state === 'bound').length}</td>
                  {#if isAdmin}
                    <td class="num">
                      <div class="row" style="gap: 6px; justify-content: flex-end">
                        <IconButton icon="edit" label="Edit" onclick={() => startEdit(tab, i)} />
                        <IconButton icon="delete" variant="danger" label="Delete {s.name}" onclick={() => removeScope(tab, i)} />
                      </div>
                    </td>
                  {/if}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      {#if tab === 'v4'}
        <p class="muted help">
          A scope serves the network it names on the interface that has an
          address in it (or the one you pick), and requests passed on by a
          DHCP relay from that network. Turn off the DHCP server on your
          router first: two servers on one network hand out conflicting
          addresses.
        </p>
      {:else}
        <p class="muted help">
          Your router still announces the network (router advertisements):
          set its "managed" flag for devices to ask this server for an
          address, or only its "other configuration" flag for them to ask for
          DNS settings. Android devices do not use DHCPv6 addresses; they get
          DNS settings from the router's advertisements. DHCPv6 relays are not
          supported.
        </p>
      {/if}
    </div>
  {:else}
    <div class="card" style="margin-bottom: 14px">
      <h3 style="margin: 0 0 10px">DHCP Server</h3>
      {#if status}
        <div class="status-grid">
          <span class="muted">DHCPv4</span><span>{status.v4}</span>
          <span class="muted">DHCPv6</span><span>{status.v6}</span>
          <span class="muted">Server DUID</span><code class="small">{status.server_duid}</code>
        </div>
        {#if !status.supported}
          <p class="err-text">DHCP is only supported on Linux.</p>
        {/if}
      {/if}
      <label class="checkbox"><input type="checkbox" bind:checked={form.enabled} disabled={!isAdmin} /><span>Run the DHCP server</span></label>
      <div class="grid2" style="margin-top: 10px">
        <label>Register Devices in Zone
          <input bind:value={form.dns_zone} list="dhcp-zones" placeholder="home.arpa" spellcheck="false" disabled={!isAdmin} />
          <datalist id="dhcp-zones">{#each zones as z (z)}<option value={z}></option>{/each}</datalist>
        </label>
      </div>
      <p class="muted help">
        Devices that give a name get an A or AAAA record in this zone (it
        must be hosted here, under Zones), and a PTR record when the matching
        reverse zone is hosted too. A name that already has records of its
        own is left alone. Leave it empty to register nothing.
      </p>
      <p class="muted help">
        DHCP uses UDP ports 67 (IPv4) and 547 (IPv6), which need the server
        to run as root or with the CAP_NET_BIND_SERVICE capability (the
        installed service has it). Only one DHCP server should run on each
        network.
      </p>
      {#if isAdmin}
        <div class="row actions">
          <button onclick={saveSettings} disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
        </div>
      {/if}
    </div>
    <div class="card">
      <h3 style="margin: 0 0 10px">Network Interfaces</h3>
      {#if interfaces.length === 0}
        <p class="muted">No interfaces found.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Interface</th><th>Addresses</th></tr></thead>
            <tbody>
              {#each interfaces as i (i.name)}
                <tr><td><code>{i.name}</code></td><td class="muted">{ifaceAddresses(i) || '-'}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}
{/if}

{#if edit}
  {@const f = edit.form}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="dhcp-title">
      <div class="spread modal-title">
        <h3 id="dhcp-title" style="margin: 0">{edit.index === null ? `Add ${edit.kind === 'v4' ? 'IPv4' : 'IPv6'} Scope` : `Edit Scope - ${f.name}`}</h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if error}<p class="dialog-error">{error}</p>{/if}
      <div class="grid2">
        <label>Name <input bind:value={f.name} placeholder={edit.kind === 'v4' ? 'LAN' : 'LAN IPv6'} /></label>
        <label>Interface
          <select bind:value={f.interface}>
            <option value="">Any with an address in the network</option>
            {#each interfaces as i (i.name)}<option value={i.name}>{i.name}</option>{/each}
            {#if f.interface && !interfaces.some((i) => i.name === f.interface)}<option value={f.interface}>{f.interface}</option>{/if}
          </select>
        </label>
      </div>
      <label class="checkbox"><input type="checkbox" bind:checked={f.enabled} /><span>Enabled</span></label>

      <div class="section-title">Addresses</div>
      {#if edit.kind === 'v4'}
        <div class="grid2">
          <label>Network <input bind:value={f.subnet} placeholder="192.168.1.0/24" spellcheck="false" /></label>
          <label>Gateway (Router) <input bind:value={f.router} placeholder="192.168.1.1" spellcheck="false" /></label>
          <label>Range Start <input bind:value={f.range_start} placeholder="192.168.1.100" spellcheck="false" /></label>
          <label>Range End <input bind:value={f.range_end} placeholder="192.168.1.199" spellcheck="false" /></label>
          <label>Lease Time (Hours) <input type="number" min="0.1" step="any" bind:value={f.lease_hours} /></label>
        </div>
      {:else}
        <div class="grid2">
          <label>Prefix <input bind:value={f.prefix} placeholder="fd00:1::/64" spellcheck="false" /></label>
        </div>
        <label class="checkbox"><input type="checkbox" bind:checked={f.stateless} /><span>DNS settings only (no addresses: stateless DHCPv6)</span></label>
        {#if !f.stateless}
          <div class="grid2" style="margin-top: 10px">
            <label>Range Start <input bind:value={f.range_start} placeholder="fd00:1::1000" spellcheck="false" /></label>
            <label>Range End <input bind:value={f.range_end} placeholder="fd00:1::1fff" spellcheck="false" /></label>
            <label>Valid Lifetime (Hours) <input type="number" min="0.1" step="any" bind:value={f.valid_hours} /></label>
            <label>Preferred Lifetime (Hours) <input type="number" min="0" step="any" bind:value={f.preferred_hours} /></label>
          </div>
        {/if}
      {/if}

      <div class="section-title">DNS</div>
      <div class="grid2">
        <label>DNS Servers <input bind:value={f.dns_servers} placeholder="Empty: this server" spellcheck="false" /></label>
        {#if edit.kind === 'v4'}
          <label>Domain Name <input bind:value={f.domain_name} placeholder="home.arpa" spellcheck="false" /></label>
          <label>NTP Servers <input bind:value={f.ntp_servers} placeholder="192.168.1.1" spellcheck="false" /></label>
        {:else}
          <label>Search Domains <input bind:value={f.domain_search} placeholder="home.arpa" spellcheck="false" /></label>
        {/if}
      </div>
      <p class="muted help">
        Separate several with commas. With no DNS servers given, devices are
        told to use this server's own address on their network.
      </p>

      {#if edit.kind === 'v4' || !f.stateless}
        <div class="section-title">Reservations</div>
        <textarea rows="4" class="mono" bind:value={f.reservations} spellcheck="false"
          placeholder={edit.kind === 'v4' ? '02:11:22:33:44:55, 192.168.1.20, printer' : '000100012a3b4c5d001122334455, fd00:1::20, nas'}></textarea>
        <p class="muted help">
          One per line: the device's {edit.kind === 'v4' ? 'MAC address' : 'DUID (shown on the Leases tab)'}, the address
          it always gets, and optionally its name. Reserved addresses may be
          outside the range.
        </p>
      {/if}

      {#if edit.kind === 'v4'}
        <div class="section-title">Other Options</div>
        <textarea rows="3" class="mono" bind:value={f.options} spellcheck="false" placeholder={'66 tftp.home.arpa\n150 0xc0a80105'}></textarea>
        <p class="muted help">
          One DHCP option per line: its number, then the value as text, or as
          hex bytes starting <code>0x</code>.
        </p>
      {/if}

      <div class="row actions">
        <button onclick={saveScope} disabled={saving || !f.name.trim()}>
          {saving ? 'Saving...' : edit.index === null ? 'Add Scope' : 'Save Scope'}
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
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .err-text { color: var(--danger); }
  .status-grid { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin-bottom: 6px; }
  .nowrap { white-space: nowrap; }
  .small { font-size: 0.78rem; }
  code { word-break: break-all; }
  tr.disabled td { opacity: 0.6; }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

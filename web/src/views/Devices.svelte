<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';
  import { loadDeviceNames } from '../devices.svelte.js';

  // Viewers are read-only (the server refuses their changes).
  const isAdmin = getStoredUser()?.role !== 'viewer';

  const PERIODS = [
    [24, 'Seen in the Last 24 Hours'],
    [24 * 7, 'Seen in the Last 7 Days'],
    [24 * 30, 'Seen in the Last 30 Days'],
  ];
  const SOURCES = { manual: 'Named Here', dhcp: 'DHCP', reverse_dns: 'Reverse DNS' };

  let hours = $state(24 * 7);
  let devices = $state([]);
  let logEnabled = $state(true);
  let loaded = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let search = $state('');
  let editing = $state(null); // { address, mac, value }
  let saving = $state(false);

  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase();
    if (!q) return devices;
    return devices.filter((d) => [d.name, d.address, d.mac].some((v) => v && v.toLowerCase().includes(q)));
  });

  async function load() {
    error = null;
    try {
      const data = await api.devices(hours);
      devices = data.devices || [];
      logEnabled = data.query_log_enabled !== false;
      loaded = true;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function startEdit(d) {
    notice = null;
    error = null;
    editing = { address: d.address, mac: d.mac, value: d.manual_name || d.name };
  }

  async function saveName(name) {
    saving = true;
    error = null;
    try {
      await api.setDeviceName(editing.address, editing.mac, name.trim());
      notice = name.trim()
        ? `${editing.address} is now called "${name.trim()}".`
        : `The name of ${editing.address} was cleared.`;
      editing = null;
      await load();
      loadDeviceNames(true);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  $effect(() => {
    hours;
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
  <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
    <h3 style="margin: 0">Devices ({devices.length})</h3>
    <div class="row" style="gap: 8px; flex-wrap: wrap">
      <input class="search" bind:value={search} placeholder="Search names and addresses" aria-label="Search devices" />
      <select bind:value={hours} aria-label="Period">
        {#each PERIODS as [value, label] (value)}<option value={value}>{label}</option>{/each}
      </select>
      <button class="secondary" onclick={load}>Reload</button>
    </div>
  </div>
  {#if !loaded}
    {#if !error}<p class="muted">Loading...</p>{/if}
  {:else if devices.length === 0}
    <p class="muted">No devices seen in this period.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Address</th><th>MAC Address</th><th>Name</th><th class="num">Queries</th><th class="num">Blocked</th><th>Last Seen</th>
            {#if isAdmin}<th class="num">Actions</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each shown as d (d.address)}
            <tr>
              <td><code>{d.address}</code></td>
              <td><code class="muted">{d.mac || '-'}</code></td>
              <td>
                {#if editing?.address === d.address}
                  <form class="row" style="gap: 6px" onsubmit={(e) => { e.preventDefault(); saveName(editing.value); }}>
                    <input bind:value={editing.value} maxlength="63" placeholder="Kids-iPad" aria-label="Device name" />
                    <button type="submit" disabled={saving}>Save</button>
                    <button type="button" class="secondary" onclick={() => (editing = null)} disabled={saving}>Cancel</button>
                  </form>
                {:else if d.name}
                  <strong>{d.name}</strong>
                  <span class="pill" title={d.source === 'manual' && d.mac ? 'Kept for this MAC address, so it follows the device to a new address' : ''}>{SOURCES[d.source] || d.source}</span>
                {:else}
                  <span class="muted">-</span>
                {/if}
              </td>
              <td class="num">{fmt(d.queries)}</td>
              <td class="num">{fmt(d.blocked)}</td>
              <td class="muted nowrap">{d.last_seen ? formatDateTime(d.last_seen) : '-'}</td>
              {#if isAdmin}
                <td class="num">
                  {#if editing?.address !== d.address}
                    <div class="row" style="gap: 6px; justify-content: flex-end">
                      <button class="secondary" onclick={() => startEdit(d)}>{d.manual_name ? 'Rename' : 'Name'}</button>
                      {#if d.manual_name}
                        <button class="secondary" onclick={() => { editing = { address: d.address, mac: d.mac, value: '' }; saveName(''); }} title="Go back to the name from DHCP or reverse DNS">Clear</button>
                      {/if}
                    </div>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if !logEnabled}
    <p class="muted help">
      The query log database is off (Settings → Logging), so only devices
      with a DHCP lease or a name are listed.
    </p>
  {/if}
  <p class="muted help">
    Devices are shown by name in the logs, reports and dashboard. A name
    given here wins; otherwise the name comes from the device's DHCP lease
    (DHCP page) or from reverse DNS (a PTR record in a hosted reverse zone,
    or from your router through a conditional forwarder). A name given to a
    device with a DHCP lease is kept for its MAC address, so it follows the
    device when its address changes. In the Query Log, a device name can be
    typed in the client filter.
  </p>
</div>

<style>
  .search { min-width: 220px; }
  .nowrap { white-space: nowrap; }
  form input { min-width: 160px; }
  code { word-break: break-all; }
</style>

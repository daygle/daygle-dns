<script>
  import { api, formatApiError } from '../api.js';
  import NetworkPicker from '../NetworkPicker.svelte';

  // Who may use this server: recursion access and the always-refused
  // networks. Saved on their own (like the other Clients tabs), so they
  // never ride along with an unsaved Settings form.
  let networks = $state([]);
  let loaded = $state(null); // the values as last saved, for "unsaved"
  let access = $state('private_networks');
  let recursionNetworks = $state([]);
  let deniedNetworks = $state([]);
  let allowedNetworks = $state([]);
  let saving = $state(false);
  let notice = $state(null);
  let error = $state(null);

  const current = () =>
    JSON.stringify([access, recursionNetworks, deniedNetworks, allowedNetworks]);
  const dirty = $derived(loaded !== null && current() !== loaded);

  async function load() {
    api.networks().then((data) => { networks = data.networks || []; }).catch(() => {});
    try {
      const config = await api.config();
      access = config.recursive?.recursion_access || 'private_networks';
      recursionNetworks = [...(config.recursive?.recursion_networks || [])];
      deniedNetworks = [...(config.policy?.denied_networks || [])];
      allowedNetworks = [...(config.policy?.allowed_networks || [])];
      loaded = current();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function save() {
    saving = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings({
        recursive: { recursion_access: access, recursion_networks: [...recursionNetworks] },
        policy: { denied_networks: [...deniedNetworks], allowed_networks: [...allowedNetworks] },
      });
      loaded = current();
      notice = 'Access saved and applied.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  $effect(() => {
    load();
  });
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card" style="margin-bottom: 14px">
  <h3 style="margin: 0 0 10px">Recursion Access</h3>
  <label class="stacked">
    <span>Who May Use Recursion</span>
    <select bind:value={access} style="max-width: 320px">
      <option value="private_networks">Private Networks Only</option>
      <option value="allow">Everyone</option>
      <option value="custom">Custom Networks</option>
      <option value="deny">Nobody</option>
    </select>
  </label>
  {#if access === 'custom'}
    <div class="stacked" style="margin-top: 12px">
      <span>Allowed Networks</span>
      <NetworkPicker {networks} bind:value={recursionNetworks} />
    </div>
  {/if}
  <p class="muted help">
    Applies to everything this server resolves rather than answers from its own
    zones; refused clients get REFUSED. Private Networks Only covers loopback,
    10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT), link-local, IPv6 ULA and
    the IPv6 networks this server is on (most LANs give devices addresses from
    the ISP's prefix rather than ULA), so the server is not an open resolver
    if it is reachable from the internet. Your own zones are answered for
    everyone. Clients allowed on a DoT, DoH or DoQ listener (Settings →
    Encrypted DNS) may also use recursion over that listener.
  </p>
</div>

<div class="card" style="margin-bottom: 14px">
  <h3 style="margin: 0 0 10px">Refused Networks</h3>
  <div class="stacked">
    <span>Always Refused (Denied)</span>
    <NetworkPicker {networks} bind:value={deniedNetworks} />
  </div>
  <div class="stacked" style="margin-top: 12px">
    <span>Exempt From the Denied List (Allowed)</span>
    <NetworkPicker {networks} bind:value={allowedNetworks} />
  </div>
  <p class="muted help">
    Clients in a denied network get REFUSED for every query, your own zones
    included, unless they are also in an allowed network.
  </p>
</div>

<div class="row actions">
  <button onclick={save} disabled={saving || !dirty}>{saving ? 'Saving...' : 'Save Access'}</button>
  <button class="secondary" onclick={load} disabled={saving}>{dirty ? 'Discard Changes' : 'Reload'}</button>
  {#if dirty}<span class="muted">Unsaved changes</span>{/if}
</div>

<style>
  .stacked { display: flex; flex-direction: column; gap: 6px; }
  .stacked > span { font-size: 0.85rem; color: var(--muted); }
  .actions { gap: 10px; align-items: center; }
</style>

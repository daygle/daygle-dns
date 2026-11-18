<script>
  import { api, formatApiError } from '../api.js';
  import SettingsForm from './SettingsForm.svelte';
  import NetworkPicker from '../NetworkPicker.svelte';

  // Zones -> Settings: defaults for new zones and records, DNSSEC signing,
  // zone transfers, dynamic updates, NOTIFY and catalog zones. Saved on its
  // own as a partial `authoritative` update, so the zone lists the other
  // tabs keep (stub zones, empty zones, ...) are never touched here.

  const DNSSEC_FIELDS = ['dnssec_enabled', 'dnssec_algorithm', 'dnssec_sig_validity_days', 'dnssec_rollover_days',
    'dnssec_rollover_overlap_days', 'dnssec_rollover_retire_days', 'dnssec_maintenance_secs'];
  // Tuning that Reset to Defaults restores; networks, NOTIFY targets,
  // the published catalog and followed catalogs are kept.
  const RESET_FIELDS = ['default_record_ttl', 'default_primary_ns', 'default_admin_mailbox', 'axfr_enabled',
    'allow_dynamic_updates', 'notify_enabled', 'notify_listen_enabled', ...DNSSEC_FIELDS];

  let authoritative = $state(null);
  // Named networks (Clients -> Networks) for the pickers.
  let networks = $state([]);
  let axfrNetworks = $state([]);
  let updateNetworks = $state([]);
  let notifyTargetsText = $state('');
  // Consumed catalog zones, as edited: masters as one comma-separated line
  // and the refresh in minutes.
  let catalogConsumers = $state([]);
  // What empty SOA defaults resolve to (this server's name, the first
  // administrator's email), for the placeholders.
  let zoneDefaults = $state(null);
  const detectedName = $derived(zoneDefaults?.server_name || null);
  const adminEmail = $derived(zoneDefaults?.first_admin_email || null);

  let savedBody = $state('');
  let busy = $state(false);
  let notice = $state(null);
  let error = $state(null);
  const dirty = $derived(authoritative != null && savedBody !== '' && JSON.stringify(buildBody()) !== savedBody);

  function parseLines(text) {
    return text.split('\n').map((l) => l.trim()).filter(Boolean);
  }

  function buildBody() {
    return {
      default_record_ttl: Number(authoritative.default_record_ttl),
      default_primary_ns: authoritative.default_primary_ns || '',
      default_admin_mailbox: (authoritative.default_admin_mailbox || '').trim(),
      axfr_enabled: !!authoritative.axfr_enabled,
      axfr_networks: [...axfrNetworks],
      allow_dynamic_updates: !!authoritative.allow_dynamic_updates,
      update_networks: [...updateNetworks],
      notify_enabled: !!authoritative.notify_enabled,
      notify_targets: parseLines(notifyTargetsText),
      notify_listen_enabled: !!authoritative.notify_listen_enabled,
      catalog_zone: (authoritative.catalog_zone || '').trim(),
      dnssec_enabled: !!authoritative.dnssec_enabled,
      dnssec_algorithm: authoritative.dnssec_algorithm || 'ECDSAP256SHA256',
      dnssec_sig_validity_days: Number(authoritative.dnssec_sig_validity_days),
      dnssec_rollover_days: Number(authoritative.dnssec_rollover_days),
      dnssec_rollover_overlap_days: Number(authoritative.dnssec_rollover_overlap_days),
      dnssec_rollover_retire_days: Number(authoritative.dnssec_rollover_retire_days),
      dnssec_maintenance_secs: Number(authoritative.dnssec_maintenance_secs),
      catalog_consumers: catalogConsumers
        .filter((c) => c.name.trim())
        .map((c) => ({
          name: c.name.trim(),
          masters: c.masters.split(/[\s,]+/).filter(Boolean),
          refresh_secs: Math.round(Number(c.refresh_minutes) * 60),
          enabled: !!c.enabled,
        })),
    };
  }

  async function load() {
    error = null;
    api.networks().then((data) => { networks = data.networks || []; }).catch(() => {});
    api.zoneDefaults().then((d) => { zoneDefaults = d; }).catch(() => {});
    try {
      const config = await api.config();
      const a = config.authoritative || {};
      authoritative = { ...a };
      axfrNetworks = [...(a.axfr_networks || [])];
      updateNetworks = [...(a.update_networks || [])];
      notifyTargetsText = (a.notify_targets || []).join('\n');
      catalogConsumers = (a.catalog_consumers || []).map((c) => ({
        name: c.name,
        masters: (c.masters || []).join(', '),
        refresh_minutes: Math.max(1, Math.round((c.refresh_secs || 3600) / 60)),
        enabled: c.enabled !== false,
      }));
      savedBody = JSON.stringify(buildBody());
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function reload() {
    if (dirty && !confirm('Discard your unsaved changes?')) return;
    notice = null;
    load();
  }

  async function save() {
    busy = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings({ authoritative: buildBody() });
      notice = 'Zone settings saved and applied.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  async function reset() {
    if (!confirm('Reset the zone settings to their defaults? Allowed networks, NOTIFY targets and catalog zones are kept. Nothing is saved until you click Save Changes.')) return;
    notice = null;
    error = null;
    try {
      const d = await api.configDefaults();
      authoritative = { ...authoritative, ...Object.fromEntries(RESET_FIELDS.map((k) => [k, d.authoritative[k]])) };
      notice = 'Zone settings reset to their defaults. Click Save Changes to apply them.';
    } catch (e) {
      error = formatApiError(e);
    }
  }

  $effect(() => {
    load();
  });
</script>

<SettingsForm loaded={authoritative != null} {dirty} {busy} {notice} {error} onSave={save} onReload={reload} onReset={reset}>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Zone Defaults</h3>
    <div class="form-grid top">
      <label><span>Default Record TTL (Seconds)</span><input type="number" min="1" bind:value={authoritative.default_record_ttl} /></label>
      <label><span>DNS Server Domain</span><input placeholder={detectedName ? `This server: ${detectedName}` : 'ns1.example.com.'} bind:value={authoritative.default_primary_ns} /></label>
      <label><span>Default Administrator Email</span><input placeholder={adminEmail ? `First administrator: ${adminEmail}` : 'hostmaster@example.com'} bind:value={authoritative.default_admin_mailbox} /></label>
    </div>
    <p class="muted help">
      The TTL is pre-filled when adding records; existing records keep their
      own. New zones use the DNS Server Domain as their primary nameserver
      and the email as their contact; leave either empty to use this
      server's own name and the first administrator's email.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNSSEC Signing</h3>
    <label class="check"><input type="checkbox" bind:checked={authoritative.dnssec_enabled} /> <span>Sign Zones That Have Signing Keys</span></label>
    <div class="form-grid" style="margin-top: 10px">
      <label><span>Signing Algorithm</span><select bind:value={authoritative.dnssec_algorithm} disabled={!authoritative.dnssec_enabled}><option value="ECDSAP256SHA256">ECDSA P-256 / SHA-256 (13)</option><option value="ECDSAP384SHA384">ECDSA P-384 / SHA-384 (14)</option><option value="ED25519">Ed25519 (15)</option></select></label>
      <label><span>Signature Validity (Days)</span><input type="number" min="1" bind:value={authoritative.dnssec_sig_validity_days} disabled={!authoritative.dnssec_enabled} /></label>
      <label><span>Roll Keys After (Days, 0 = Never)</span><input type="number" min="0" bind:value={authoritative.dnssec_rollover_days} disabled={!authoritative.dnssec_enabled} /></label>
      <label><span>Old and New Key Overlap (Days)</span><input type="number" min="1" bind:value={authoritative.dnssec_rollover_overlap_days} disabled={!authoritative.dnssec_enabled} /></label>
      <label><span>Keep Retired Key Published (Days)</span><input type="number" min="1" bind:value={authoritative.dnssec_rollover_retire_days} disabled={!authoritative.dnssec_enabled} /></label>
      <label><span>Check Every (Seconds)</span><input type="number" min="60" bind:value={authoritative.dnssec_maintenance_secs} disabled={!authoritative.dnssec_enabled} /></label>
    </div>
    <p class="muted help">
      Signatures last for the validity period and are renewed automatically at
      half of it. When key rollover is on, a key older than the rollover age
      is replaced: both keys sign for the overlap period (submit the new DS
      record to your registrar then), and the old key stays published for the
      retire period so cached signatures still verify. Turning signing on or
      off, or changing the validity, re-signs the zones at once; the other
      settings apply at the next check. A changed algorithm is used for the
      next key: rolling a key publishes both keys while you update the DS
      record. Keys are managed per zone on the Zones tab.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Zone Transfers (AXFR/IXFR)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.axfr_enabled} /> <span>Allow Zone Transfers</span></label>
    </div>
    <div class="stacked">
      <span>Allowed Networks</span>
      <NetworkPicker {networks} bind:value={axfrNetworks} />
    </div>
    <p class="muted help">
      Only these networks may request a copy of your zones. An empty list allows
      every client when transfers are enabled - restrict this to trusted hosts.
      Applies immediately, no restart needed.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Dynamic Updates (RFC 2136)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.allow_dynamic_updates} /> <span>Accept Dynamic Updates</span></label>
    </div>
    <div class="stacked">
      <span>Allowed Networks</span>
      <NetworkPicker {networks} bind:value={updateNetworks} />
    </div>
    <p class="muted help">
      Clients on these networks may add, change, or delete records in primary
      zones with UPDATE messages. With an empty list, only zones bound to a
      TSIG key accept updates, and only signed ones. Applies immediately, no
      restart needed.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">NOTIFY (RFC 1996)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.notify_enabled} /> <span>Send NOTIFY to Secondaries</span></label>
      <label class="check"><input type="checkbox" bind:checked={authoritative.notify_listen_enabled} /> <span>Accept NOTIFY from Masters</span></label>
    </div>
    <label class="stacked">
      <span>NOTIFY Targets (one per line: IP, IP:port, or [IPv6]:port)</span>
      <textarea rows="3" placeholder={"198.51.100.10\n198.51.100.11:5353"} bind:value={notifyTargetsText}></textarea>
    </label>
    <p class="muted help">
      When a primary zone changes, the server notifies these targets so their
      secondary copies refresh immediately. Enabling or disabling NOTIFY takes
      effect after a restart; the target list is saved right away.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Catalog Zones (RFC 9432)</h3>
    <div class="form-grid">
      <label><span>Publish a Catalog Named</span><input placeholder="catalog.example.com" bind:value={authoritative.catalog_zone} /></label>
    </div>
    <p class="muted help">
      Lists every primary zone on this server in a catalog zone, so secondaries
      that follow it (BIND, Knot, PowerDNS or another Daygle DNS server) add and
      remove zones on their own. They transfer it like any zone, so allow them
      under Zone Transfers; with NOTIFY on, they are told when the list changes.
      Leave empty to publish no catalog.
    </p>
    <h4 style="margin: 14px 0 8px">Follow Catalogs</h4>
    {#each catalogConsumers as consumer, i}
      <div class="form-grid" style="align-items: end; margin-bottom: 8px">
        <label><span>Catalog Zone</span><input placeholder="catalog.example.com" bind:value={consumer.name} /></label>
        <label><span>Masters (IP, IP:port; comma-separated)</span><input placeholder="198.51.100.10" bind:value={consumer.masters} /></label>
        <label><span>Check Every (Minutes)</span><input type="number" min="1" bind:value={consumer.refresh_minutes} /></label>
        <div class="row" style="gap: 10px">
          <label class="check"><input type="checkbox" bind:checked={consumer.enabled} /> <span>Enabled</span></label>
          <button class="danger" onclick={() => (catalogConsumers = catalogConsumers.filter((_, j) => j !== i))} aria-label="Stop following {consumer.name || 'this catalog'}">✕</button>
        </div>
      </div>
    {/each}
    <button class="secondary" onclick={() => (catalogConsumers = [...catalogConsumers, { name: '', masters: '', refresh_minutes: 60, enabled: true }])}>Add Catalog</button>
    <p class="muted help">
      Every zone a followed catalog lists is served here as a secondary zone,
      transferred from the catalog's masters; zones it drops are removed. A
      disabled catalog keeps its zones but stops changing them; removing it
      removes them. With Accept NOTIFY on, a NOTIFY from a master checks the
      catalog at once. Applies immediately, no restart needed.
    </p>
  </div>
</SettingsForm>

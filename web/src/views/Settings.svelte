<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { prefs, setDateTimePrefs, timeZoneOptions, FORMAT_OPTIONS, formatDateTime } from '../datetime.svelte.js';

  let config = $state(null);
  let notice = $state(null);
  let error = $state(null);
  let busy = $state(false);

  // Settings is split into tabs (same pattern as the Logs page) so the page
  // stays navigable as more options are added.
  let tab = $state('general');
  const TABS = [
    ['general', 'General'],
    ['recursive', 'Recursive & Caching'],
    ['listeners', 'Protocol Listeners'],
    ['zones', 'Zones & Records'],
    ['interface', 'Interface'],
  ];

  // Local editable copies (bound to the form inputs).
  let server = $state({});
  let recursive = $state({});
  let authoritative = $state({});
  let dot = $state({});
  let doh = $state({});
  let doq = $state({});
  let api_ = $state({});
  let upstreamText = $state('');
  // Multi-line textareas for the network allow-lists and NOTIFY targets.
  let axfrNetworksText = $state('');
  let updateNetworksText = $state('');
  let notifyTargetsText = $state('');

  // Console-managed certificates available for the DoT/DoH/DoQ listeners.
  let certs = $state([]);
  // Certificate picker mode per listener: 'self' (auto self-signed), 'custom'
  // (raw file paths), or the name of a managed certificate.
  let dotCertMode = $state('self');
  let dohCertMode = $state('self');
  let doqCertMode = $state('self');

  // Local copies of the display preferences (saved instantly on change).
  let tzDraft = $state(prefs.tz);
  let formatDraft = $state(prefs.format);
  const zoneChoices = timeZoneOptions();

  function applyDisplayPrefs() {
    setDateTimePrefs({ tz: tzDraft, format: formatDraft });
  }

  $effect(() => {
    load();
    api.certificates().then((list) => { certs = list || []; }).catch(() => {});
  });

  // Translate the config's certificate state into a picker value.
  function certModeOf(listener) {
    if (listener.certificate) return listener.certificate;
    if (listener.self_signed) return 'self';
    return 'custom';
  }

  function applyCertMode(listener, value) {
    if (value === 'self') {
      listener.self_signed = true;
      listener.certificate = '';
    } else if (value === 'custom') {
      listener.self_signed = false;
      listener.certificate = '';
    } else {
      listener.self_signed = false;
      listener.certificate = value;
    }
  }

  async function load() {
    error = null;
    try {
      config = await api.config();
      if (config == null) {
        server = {};
        recursive = {};
        authoritative = {};
        dot = {};
        doh = {};
        doq = {};
        api_ = {};
        upstreamText = '';
        axfrNetworksText = '';
        updateNetworksText = '';
        notifyTargetsText = '';
        return;
      }
      server = { ...config.server };
      recursive = { ...config.recursive };
      authoritative = { ...config.authoritative };
      dot = { ...config.dot };
      doh = { ...config.doh };
      doq = { ...config.doq };
      api_ = { ...config.api };
      dotCertMode = certModeOf(dot);
      dohCertMode = certModeOf(doh);
      doqCertMode = certModeOf(doq);
      upstreamText = (recursive.upstreams || []).join('\n');
      axfrNetworksText = (authoritative.axfr_networks || []).join('\n');
      updateNetworksText = (authoritative.update_networks || []).join('\n');
      notifyTargetsText = (authoritative.notify_targets || []).join('\n');
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function parseUpstreams(text) {
    return text.split('\n').map((l) => l.trim()).filter(Boolean);
  }

  // Trim each line and drop empties (shared by the network allow-lists and
  // NOTIFY targets, which are all newline-separated textareas).
  function parseLines(text) {
    return text.split('\n').map((l) => l.trim()).filter(Boolean);
  }

  async function clearCache() {
    busy = true;
    notice = null;
    error = null;
    try {
      await api.clearCache();
      notice = 'Recursive cache flushed.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  async function save() {
    busy = true;
    notice = null;
    error = null;
    try {
      const body = {
        server: {
          listen: server.listen,
          port: Number(server.port),
          udp_enabled: !!server.udp_enabled,
          tcp_enabled: !!server.tcp_enabled,
          reload_enabled: !!server.reload_enabled,
        },
        recursive: {
          enabled: !!recursive.enabled,
          upstreams: parseUpstreams(upstreamText),
          dnssec_validate: !!recursive.dnssec_validate,
          prefetch_enabled: !!recursive.prefetch_enabled,
          prefetch_ttl_fraction_pct: Number(recursive.prefetch_ttl_fraction_pct),
          prefetch_min_queries: Number(recursive.prefetch_min_queries),
          serve_stale_secs: Number(recursive.serve_stale_secs),
          max_cache_ttl: Number(recursive.max_cache_ttl),
          failure_cache_ttl: Number(recursive.failure_cache_ttl),
        },
        dot: {
          enabled: !!dot.enabled,
          port: Number(dot.port),
          self_signed: !!dot.self_signed,
          server_name: dot.server_name,
          cert_path: dot.cert_path || '',
          key_path: dot.key_path || '',
          certificate: dot.certificate || '',
        },
        doh: {
          enabled: !!doh.enabled,
          port: Number(doh.port),
          self_signed: !!doh.self_signed,
          server_name: doh.server_name,
          cert_path: doh.cert_path || '',
          key_path: doh.key_path || '',
          certificate: doh.certificate || '',
          endpoint: doh.endpoint,
        },
        doq: {
          enabled: !!doq.enabled,
          port: Number(doq.port),
          self_signed: !!doq.self_signed,
          server_name: doq.server_name,
          cert_path: doq.cert_path || '',
          key_path: doq.key_path || '',
          certificate: doq.certificate || '',
        },
        api: {
          gui_enabled: !!api_.gui_enabled,
          cors_origins: api_.cors_origins || [],
        },
        authoritative: {
          default_record_ttl: Number(authoritative.default_record_ttl),
          axfr_enabled: !!authoritative.axfr_enabled,
          axfr_networks: parseLines(axfrNetworksText),
          allow_dynamic_updates: !!authoritative.allow_dynamic_updates,
          update_networks: parseLines(updateNetworksText),
          notify_enabled: !!authoritative.notify_enabled,
          notify_targets: parseLines(notifyTargetsText),
          notify_listen_enabled: !!authoritative.notify_listen_enabled,
        },
      };
      await api.updateSettings(body);
      notice = 'Settings saved: applied live and stored in the database.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader icon={icons.settings} title="Settings" />

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if config}
  <div class="tabs">
    {#each TABS as [id, label] (id)}
      <button class="tab" class:active={tab === id} onclick={() => (tab = id)}>{label}</button>
    {/each}
  </div>

  <div class="actions">
    <button onclick={save} disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
    <button class="secondary" onclick={load} disabled={busy}>Reload</button>
    {#if tab === 'recursive'}
      <button class="secondary" onclick={clearCache}>Flush Cache</button>
    {/if}
  </div>

  {#if tab === 'general'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">DNS Listeners</h3>
    <div class="form-grid">
      <label><span>Listen Address</span><input bind:value={server.listen} /></label>
      <label><span>UDP/TCP Port</span><input type="number" bind:value={server.port} /></label>
      <label class="check"><input type="checkbox" bind:checked={server.udp_enabled} /> <span>UDP Enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={server.tcp_enabled} /> <span>TCP Enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={server.reload_enabled} /> <span>Live Config Reload</span></label>
    </div>
  </div>
  {:else if tab === 'recursive'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Recursive Resolver</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={recursive.enabled} /> <span>Recursion Enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={recursive.dnssec_validate} /> <span>DNSSEC Validation</span></label>
      <label class="check"><input type="checkbox" bind:checked={recursive.use_system_config} /> <span>Use System DNS Configuration</span></label>
      <label><span>Upstream Servers (one per line; supports <code>tls://</code> and <code>https://</code>)</span>
        <textarea rows="4" bind:value={upstreamText}></textarea>
      </label>
    </div>
    <h4>Caching</h4>
    <div class="form-grid">
      <label><span>Minimum Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.min_cache_ttl} /></label>
      <label><span>Negative Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.negative_cache_ttl} /></label>
      <label><span>Maximum Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.max_cache_ttl} /></label>
      <label><span>Failure Cache TTL (Seconds)</span><input type="number" min="0" bind:value={recursive.failure_cache_ttl} /></label>
      <label><span>Cache Size (Entries)</span><input type="number" min="0" bind:value={recursive.cache_size} /></label>
      <label class="check"><input type="checkbox" bind:checked={recursive.prefetch_enabled} /> <span>Refresh Popular Names Early</span></label>
      <label><span>Prefetch Trigger (TTL Fraction %)</span><input type="number" min="1" max="99" bind:value={recursive.prefetch_ttl_fraction_pct} /></label>
      <label><span>Prefetch Minimum Queries</span><input type="number" min="1" bind:value={recursive.prefetch_min_queries} /></label>
      <label><span>Serve-Stale Window (Seconds)</span><input type="number" min="0" bind:value={recursive.serve_stale_secs} /></label>
    </div>
    <p class="muted help">
      Minimum and negative TTLs bound how long records stay in cache. Maximum TTL
      clamps positive answers at insert time so tracking-heavy domains cannot pin
      themselves in cache for weeks. Failure Cache TTL caches SERVFAIL and other
      upstream errors briefly so a broken upstream is not hammered on every query;
      set it to 0 to disable.
    </p>
  </div>
  {:else if tab === 'zones'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Records</h3>
    <div class="form-grid">
      <label><span>Default Record TTL (Seconds)</span><input type="number" min="1" bind:value={authoritative.default_record_ttl} /></label>
    </div>
    <p class="muted help">
      Pre-filled when adding records on the Records page. Existing records keep
      their own TTL; change it there when needed.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Zone Transfers (AXFR/IXFR)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.axfr_enabled} /> <span>Allow Zone Transfers</span></label>
    </div>
    <label class="stacked">
      <span>Allowed Networks (one CIDR per line, e.g. 192.168.1.0/24)</span>
      <textarea rows="3" placeholder="192.168.1.0/24\n10.0.0.0/8" bind:value={axfrNetworksText}></textarea>
    </label>
    <p class="muted help">
      Only these networks may request a copy of your zones. An empty list allows
      every client when transfers are enabled - restrict this to trusted hosts.
      Applies immediately, no restart needed.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Dynamic Updates (RFC 2136)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.allow_dynamic_updates} /> <span>Accept Dynamic Updates</span></label>
    </div>
    <label class="stacked">
      <span>Allowed Networks (one CIDR per line)</span>
      <textarea rows="3" placeholder="192.168.1.0/24" bind:value={updateNetworksText}></textarea>
    </label>
    <p class="muted help">
      Clients on these networks may add, change, or delete records in primary
      zones with UPDATE messages. An empty list allows every client when
      dynamic updates are enabled. Applies immediately, no restart needed.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">NOTIFY (RFC 1996)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.notify_enabled} /> <span>Send NOTIFY to Secondaries</span></label>
      <label class="check"><input type="checkbox" bind:checked={authoritative.notify_listen_enabled} /> <span>Accept NOTIFY From Masters</span></label>
    </div>
    <label class="stacked">
      <span>NOTIFY Targets (one per line: IP, IP:port, or [IPv6]:port)</span>
      <textarea rows="3" placeholder="198.51.100.10\n198.51.100.11:5353" bind:value={notifyTargetsText}></textarea>
    </label>
    <p class="muted help">
      When a primary zone changes, the server notifies these targets so their
      secondary copies refresh immediately. Enabling or disabling NOTIFY takes
      effect after a restart; the target list is saved right away.
    </p>
  </div>
  {:else if tab === 'listeners'}
  <div class="row" style="margin-bottom: 14px; align-items: stretch">
    <div class="card" style="flex: 1">
      <h3 style="margin-top: 0">DNS over TLS</h3>
      <div class="form-grid">
        <label class="check"><input type="checkbox" bind:checked={dot.enabled} /> <span>Enabled</span></label>
        <label><span>Port</span><input type="number" bind:value={dot.port} /></label>
        <label>
          <span>Certificate</span>
          <select bind:value={dotCertMode} onchange={(e) => applyCertMode(dot, e.currentTarget.value)}>
            <option value="self">Self-signed (auto)</option>
            {#each certs as cert (cert.name)}
              <option value={cert.name}>{cert.name}{cert.server_name ? ` - ${cert.server_name}` : ''}</option>
            {/each}
            <option value="custom">Custom files…</option>
          </select>
        </label>
        {#if dotCertMode === 'self'}
          <label><span>Certificate Name</span><input bind:value={dot.server_name} placeholder="dns.example.com" /></label>
        {:else if dotCertMode === 'custom'}
          <label><span>Certificate Path</span><input bind:value={dot.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
          <label><span>Key Path</span><input bind:value={dot.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
        {/if}
      </div>
    </div>
    <div class="card" style="flex: 1">
      <h3 style="margin-top: 0">DNS over HTTPS</h3>
      <div class="form-grid">
        <label class="check"><input type="checkbox" bind:checked={doh.enabled} /> <span>Enabled</span></label>
        <label><span>Port</span><input type="number" bind:value={doh.port} /></label>
        <label>
          <span>Certificate</span>
          <select bind:value={dohCertMode} onchange={(e) => applyCertMode(doh, e.currentTarget.value)}>
            <option value="self">Self-signed (auto)</option>
            {#each certs as cert (cert.name)}
              <option value={cert.name}>{cert.name}{cert.server_name ? ` - ${cert.server_name}` : ''}</option>
            {/each}
            <option value="custom">Custom files…</option>
          </select>
        </label>
        {#if dohCertMode === 'self'}
          <label><span>Certificate Name</span><input bind:value={doh.server_name} placeholder="dns.example.com" /></label>
        {:else if dohCertMode === 'custom'}
          <label><span>Certificate Path</span><input bind:value={doh.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
          <label><span>Key Path</span><input bind:value={doh.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
        {/if}
        <label><span>Endpoint Path</span><input bind:value={doh.endpoint} /></label>
      </div>
    </div>
    <div class="card" style="flex: 1">
      <h3 style="margin-top: 0">DNS over QUIC</h3>
      <div class="form-grid">
        <label class="check"><input type="checkbox" bind:checked={doq.enabled} /> <span>Enabled</span></label>
        <label><span>Port</span><input type="number" bind:value={doq.port} /></label>
        <label>
          <span>Certificate</span>
          <select bind:value={doqCertMode} onchange={(e) => applyCertMode(doq, e.currentTarget.value)}>
            <option value="self">Self-signed (auto)</option>
            {#each certs as cert (cert.name)}
              <option value={cert.name}>{cert.name}{cert.server_name ? ` - ${cert.server_name}` : ''}</option>
            {/each}
            <option value="custom">Custom files…</option>
          </select>
        </label>
        {#if doqCertMode === 'self'}
          <label><span>Certificate Name</span><input bind:value={doq.server_name} placeholder="dns.example.com" /></label>
        {:else if doqCertMode === 'custom'}
          <label><span>Certificate Path</span><input bind:value={doq.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
          <label><span>Key Path</span><input bind:value={doq.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
        {/if}
      </div>
    </div>
  </div>
  {:else if tab === 'interface'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Display</h3>
    <div class="form-grid">
      <label><span>Time Zone</span>
        <select bind:value={tzDraft} onchange={applyDisplayPrefs}>
          {#each zoneChoices as [value, label]}<option value={value}>{label}</option>{/each}
        </select>
      </label>
      <label><span>Date & Time Format</span>
        <select bind:value={formatDraft} onchange={applyDisplayPrefs}>
          {#each FORMAT_OPTIONS as [value, label]}<option value={value}>{label}</option>{/each}
        </select>
      </label>
    </div>
    <p class="muted" style="font-size: 0.85rem; margin-bottom: 0">
      Example with the current choice: <strong>{formatDateTime(new Date())}</strong>. Display
      preferences are per browser and apply everywhere dates and times are shown.
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Console</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={api_.gui_enabled} /> <span>Serve the Web GUI</span></label>
    </div>
    <p class="muted" style="font-size: 0.85rem">
      The settings on this page are stored in the server database and survive
      restarts. Bootstrap options (listen addresses, ports, certificate paths,
      login accounts and zone signing) are edited in
      <code>daygle-dns.toml</code>. Changes here are validated first - an
      invalid value is rejected and nothing is applied.
    </p>
  </div>
  {/if}
{:else}
  <p class="muted">Loading…</p>
{/if}

<style>
  .actions { display: flex; gap: 10px; margin-bottom: 16px; }
  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 14px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .tab {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 14px;
    cursor: pointer;
    color: var(--muted);
    font: inherit;
  }
  .tab.active {
    color: var(--text);
    border-bottom-color: var(--accent);
  }
  .stacked {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 4px;
  }
  .help {
    font-size: 0.82rem;
    line-height: 1.45;
    margin: 6px 0 0;
  }
  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
    align-items: end;
  }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  label.check {
    flex-direction: row;
    align-items: center;
    gap: 8px;
    padding-bottom: 8px;
  }
  label.check span { color: var(--text); }
  textarea {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 8px;
    font: inherit;
    color: inherit;
    resize: vertical;
  }
  h4 { margin: 14px 0 8px; }
</style>

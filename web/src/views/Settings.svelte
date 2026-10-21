<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import ClientPolicies from './ClientPolicies.svelte';
  import BackupRestore from './BackupRestore.svelte';
  import { icons } from '../icons.svelte.js';
  import { display, setDisplayDefaults, timeZoneOptions, DATE_FORMAT_OPTIONS, TIME_FORMAT_OPTIONS, previewDateTime } from '../datetime.svelte.js';
  import { duration } from '../aiLabels.js';

  let config = $state(null);
  let notice = $state(null);
  let error = $state(null);
  let busy = $state(false);

  // Settings is split into tabs (same pattern as the Logs page) so the page
  // stays navigable as more options are added.
  // `initialTab` lets another page open a tab directly (the Cache page's
  // "Settings" button).
  let { initialTab = 'general' } = $props();
  let tab = $state(initialTab);
  const TABS = [
    ['general', 'General'],
    ['recursive', 'Resolver'],
    ['cache', 'Cache'],
    ['listeners', 'Encrypted DNS'],
    ['zones', 'Zones'],
    ['ai', 'AI Scanner'],
    ['interface', 'Interface'],
    ['backup', 'Backup'],
  ];
  const TAGLINES = {
    general: 'How the web console is reached (HTTP, HTTPS or both), and the DNS listeners this server was started with.',
    recursive: 'How the server answers names it does not host: resolving them itself from the root servers or forwarding to upstreams, and who may use it.',
    cache: 'How long answers are kept, how many, and how popular names are refreshed before they expire. Changes apply immediately.',
    listeners: 'Encrypted DNS: DNS over TLS, HTTPS and QUIC, and the certificate each one presents. Changes apply immediately.',
    zones: 'Defaults for new zones and records, and how other DNS servers may copy, update and be notified about your zones.',
    ai: 'The background scanner that classifies the domains in your DNS traffic and can block unsafe ones.',
    interface: 'How the console shows dates and times by default.',
    backup: 'Download a backup of everything this server keeps, or restore one.',
  };

  // Local editable copies (bound to the form inputs).
  let server = $state({});
  let recursive = $state({});
  let authoritative = $state({});
  let dot = $state({});
  let doh = $state({});
  let doq = $state({});
  let api_ = $state({});
  let ai_ = $state({});
  // AI values in the units the form shows (minutes, days, percent); turned
  // back into seconds and fractions on save.
  let aiForm = $state({});
  // Whether a scanner is running now (it is only built at startup).
  let aiRunning = $state(false);
  // Auto-block categories as a comma-separated text input.
  let aiCategoriesText = $state('');
  // The loaded backend's own category list (model labels / heuristic rules);
  // empty when unavailable, in which case the text field is the only UI.
  let aiBackendCategories = $state([]);
  let upstreamText = $state('');
  let recursionNetworksText = $state('');
  // Multi-line textareas for the network allow-lists and NOTIFY targets.
  let axfrNetworksText = $state('');
  let updateNetworksText = $state('');
  let notifyTargetsText = $state('');
  // Consumed catalog zones, as edited: masters as one comma-separated line
  // and the refresh in minutes.
  let catalogConsumers = $state([]);

  // Console-managed certificates available for the DoT/DoH/DoQ listeners.
  let certs = $state([]);
  // Certificate picker mode per listener: 'self' (auto self-signed), 'custom'
  // (raw file paths), or the name of a managed certificate.
  let dotCertMode = $state('self');
  let dohCertMode = $state('self');
  let doqCertMode = $state('self');

  // The saved form, to tell whether anything has changed since.
  let savedBody = $state('');
  const dirty = $derived(config != null && savedBody !== '' && JSON.stringify(buildBody()) !== savedBody);

  // "3600" -> "1 Hour", shown beside seconds fields.
  function hint(secs) {
    const n = Number(secs);
    return Number.isInteger(n) && n > 0 ? duration(n) : '';
  }

  // Server-wide date and time display defaults (saved with the page).
  let display_ = $state({ time_zone: 'system', date_format: 'system', time_format: 'system' });
  // How the web console is served (Settings -> General). `http_port` 0 in
  // the stored settings means the config file's api.port; the form shows
  // the real number.
  let web_ = $state({ http_enabled: true, http_port: 5380, https_enabled: false, https_port: 5443, https_certificate: '', redirect_http: false });
  // Remote logging (Settings -> General).
  let dns64 = $state({ enabled: false, prefix: '64:ff9b::/96' });
  let dns64ClientsText = $state('');
  let ecs = $state({ enabled: false, subnet: '', ipv4_prefix: 24, ipv6_prefix: 56 });
  let syslog_ = $state({ enabled: false, server: '', facility: 'daemon', level: 'info', queries: false });
  const zoneChoices = timeZoneOptions();
  // Users who chose their own settings don't see the defaults change.
  const ownPrefsSet = $derived(
    !!(display.mine && (display.mine.time_zone || display.mine.date_format || display.mine.time_format)),
  );

  // What empty SOA defaults resolve to (this server's name, the first
  // administrator's email), for the Zones tab placeholders.
  let zoneDefaults = $state(null);

  $effect(() => {
    load();
    api.certificates().then((list) => { certs = list || []; }).catch(() => {});
    api.zoneDefaults().then((d) => { zoneDefaults = d; }).catch(() => {});
  });

  // A managed certificate in the picker, flagged when it is not usable.
  function certLabel(cert) {
    const names = (cert.names || []).filter((n) => n !== 'localhost');
    let label = names.length ? `${cert.name} - ${names[0]}` : cert.server_name ? `${cert.name} - ${cert.server_name}` : cert.name;
    if (cert.not_after && Date.parse(cert.not_after) <= Date.now()) label += ' (Expired)';
    return label;
  }

  // The automatic values an empty SOA default falls back to.
  const detectedName = $derived(zoneDefaults?.server_name || null);
  const adminEmail = $derived(zoneDefaults?.first_admin_email || null);

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
    // Saving HTTPS can create the web-console certificate; keep the
    // pickers current.
    api.certificates().then((list) => { certs = list || []; }).catch(() => {});
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
        ai_ = {};
        display_ = { time_zone: 'system', date_format: 'system', time_format: 'system' };
        aiCategoriesText = '';
        aiBackendCategories = [];
        upstreamText = '';
        recursionNetworksText = '';
        axfrNetworksText = '';
        updateNetworksText = '';
        notifyTargetsText = '';
        return;
      }
      server = { ...config.server };
      recursive = { ...config.recursive };
      // An unset mode means: forwarding when upstreams exist, else recursive.
      recursive.mode = config.recursive.mode || (config.recursive.upstreams?.length ? 'forwarding' : 'recursive');
      recursive.recursion_access = config.recursive.recursion_access || 'private_networks';
      recursive.outbound_ip_versions = config.recursive.outbound_ip_versions || 'both';
      recursionNetworksText = (config.recursive.recursion_networks || []).join('\n');
      authoritative = { ...config.authoritative };
      dot = { ...config.dot };
      doh = { ...config.doh };
      doq = { ...config.doq };
      api_ = { ...config.api };
      display_ = { time_zone: 'system', date_format: 'system', time_format: 'system', ...config.display };
      web_ = {
        http_enabled: true, https_enabled: false, https_port: 5443, https_certificate: '', redirect_http: false,
        ...config.web,
        http_port: config.web?.http_port || config.api?.port || 5380,
      };
      syslog_ = { enabled: false, server: '', facility: 'daemon', level: 'info', queries: false, ...config.syslog };
      dns64 = { enabled: !!config.dns64?.enabled, prefix: config.dns64?.prefix || '64:ff9b::/96' };
      dns64ClientsText = (config.dns64?.clients || []).join('\n');
      ecs = { enabled: false, subnet: '', ipv4_prefix: 24, ipv6_prefix: 56, ...config.ecs };
      ai_ = { ...config.ai, mode: config.ai?.mode || 'train' };
      aiForm = {
        scanMinutes: round2(ai_.scan_interval_secs / 60),
        expireMinutes: round2(ai_.expire_check_secs / 60),
        threatDays: round2(ai_.threat_ttl_secs / 86400),
        categoryDays: round2(ai_.category_ttl_secs / 86400),
        thresholdPct: round2(ai_.block_threshold * 100),
        floorPct: round2(ai_.confidence_floor * 100),
      };
      aiCategoriesText = (config.ai?.auto_block_categories || []).join(', ');
      api
        .aiStatus()
        .then((s) => {
          aiBackendCategories = s?.backend_categories || [];
          aiRunning = true;
        })
        .catch(() => {
          aiRunning = false;
        })
        // The category picker changes how the form reads; it is still the
        // saved state.
        .finally(() => {
          savedBody = JSON.stringify(buildBody());
        });
      dotCertMode = certModeOf(dot);
      dohCertMode = certModeOf(doh);
      doqCertMode = certModeOf(doq);
      upstreamText = (recursive.upstreams || []).join('\n');
      axfrNetworksText = (authoritative.axfr_networks || []).join('\n');
      updateNetworksText = (authoritative.update_networks || []).join('\n');
      notifyTargetsText = (authoritative.notify_targets || []).join('\n');
      catalogConsumers = (authoritative.catalog_consumers || []).map((c) => ({
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

  function parseUpstreams(text) {
    return text.split('\n').map((l) => l.trim()).filter(Boolean);
  }

  // What a listen setting accepts, in words. It is one address or several
  // separated by commas; `::` is dual-stack unless server.ipv6_only is set
  // or the list also names IPv4 addresses.
  function listenMeaning(listen, ipv6Only) {
    const parts = String(listen || '').split(',').map((p) => p.trim().replace(/^\[(.*)\]$/, '$1')).filter(Boolean);
    if (parts.length === 1) {
      const a = parts[0];
      if (a === '0.0.0.0') return 'All IPv4 addresses';
      if (a === '::') return ipv6Only ? 'All IPv6 addresses (IPv6 only)' : 'All IPv4 and IPv6 addresses';
      if (a === '127.0.0.1' || a === '::1') return 'This computer only';
      return a.includes(':') ? 'This IPv6 address only' : 'This IPv4 address only';
    }
    const wildcards = parts.filter((p) => p === '0.0.0.0' || p === '::')
      .map((p) => (p === '::' ? 'all IPv6 addresses' : 'all IPv4 addresses'));
    const others = parts.length - wildcards.length;
    const text = [...wildcards, others ? `${others} specific address${others > 1 ? 'es' : ''}` : '']
      .filter(Boolean).join(' and ');
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  // Trim each line and drop empties (shared by the network allow-lists and
  // NOTIFY targets, which are all newline-separated textareas).
  function parseLines(text) {
    return text.split('\n').map((l) => l.trim()).filter(Boolean);
  }


  // Everything the page edits, in the shape PUT /api/config takes. The
  // General tab's listeners and the console switch are config-file owned
  // (a broken listener can always be fixed by editing the file), so they
  // are shown but not sent.
  function buildBody() {
    return {
      recursive: {
        enabled: !!recursive.enabled,
        mode: recursive.mode,
        recursion_access: recursive.recursion_access,
        recursion_networks: parseLines(recursionNetworksText),
        case_randomization: !!recursive.case_randomization,
        rebinding_protection: !!recursive.rebinding_protection,
        opportunistic_encryption: !!recursive.opportunistic_encryption,
        outbound_ip_versions: recursive.outbound_ip_versions,
        upstreams: parseUpstreams(upstreamText),
        use_system_config: !!recursive.use_system_config,
        cache_size: Number(recursive.cache_size),
        min_cache_ttl: Number(recursive.min_cache_ttl),
        negative_cache_ttl: Number(recursive.negative_cache_ttl),
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
        handshake_timeout_secs: Number(dot.handshake_timeout_secs),
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
        handshake_timeout_secs: Number(doh.handshake_timeout_secs),
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
      display: { ...display_ },
      web: {
        http_enabled: !!web_.http_enabled,
        http_port: Number(web_.http_port),
        https_enabled: !!web_.https_enabled,
        https_port: Number(web_.https_port),
        https_certificate: web_.https_certificate || '',
        redirect_http: !!(web_.redirect_http && web_.http_enabled && web_.https_enabled),
      },
      dns64: {
        enabled: !!dns64.enabled,
        prefix: (dns64.prefix || '').trim(),
        clients: parseLines(dns64ClientsText),
      },
      ecs: {
        enabled: !!ecs.enabled,
        subnet: (ecs.subnet || '').trim(),
        ipv4_prefix: Number(ecs.ipv4_prefix),
        ipv6_prefix: Number(ecs.ipv6_prefix),
      },
      syslog: {
        enabled: !!syslog_.enabled,
        server: (syslog_.server || '').trim(),
        facility: syslog_.facility || 'daemon',
        level: syslog_.level || 'info',
        queries: !!syslog_.queries,
      },
      authoritative: {
        default_record_ttl: Number(authoritative.default_record_ttl),
        default_primary_ns: authoritative.default_primary_ns || '',
        default_admin_mailbox: (authoritative.default_admin_mailbox || '').trim(),
        axfr_enabled: !!authoritative.axfr_enabled,
        axfr_networks: parseLines(axfrNetworksText),
        allow_dynamic_updates: !!authoritative.allow_dynamic_updates,
        update_networks: parseLines(updateNetworksText),
        notify_enabled: !!authoritative.notify_enabled,
        notify_targets: parseLines(notifyTargetsText),
        notify_listen_enabled: !!authoritative.notify_listen_enabled,
        catalog_zone: (authoritative.catalog_zone || '').trim(),
        catalog_consumers: catalogConsumers
          .filter((c) => c.name.trim())
          .map((c) => ({
            name: c.name.trim(),
            masters: c.masters.split(/[\s,]+/).filter(Boolean),
            refresh_secs: Math.round(Number(c.refresh_minutes) * 60),
            enabled: !!c.enabled,
          })),
      },
      ai: {
        enabled: !!ai_.enabled,
        mode: ai_.mode || 'train',
        database: ai_.database || '',
        model_path: ai_.model_path || '',
        workers: Number(ai_.workers),
        scan_interval_secs: Math.round(Number(aiForm.scanMinutes) * 60),
        expire_check_secs: Math.round(Number(aiForm.expireMinutes) * 60),
        max_domains_per_scan: Number(ai_.max_domains_per_scan),
        auto_block_categories:
          aiBackendCategories.length
            ? aiBackendCategories.filter((c) => aiSelectedCategories().includes(c))
            : (aiCategoriesText || '').split(',').map((c) => c.trim()).filter(Boolean),
        block_threshold: Number(aiForm.thresholdPct) / 100,
        confidence_floor: Number(aiForm.floorPct) / 100,
        category_ttl_secs: Math.round(Number(aiForm.categoryDays) * 86400),
        threat_ttl_secs: Math.round(Number(aiForm.threatDays) * 86400),
      },
    };
  }

  async function save() {
    busy = true;
    notice = null;
    error = null;
    try {
      const body = buildBody();
      await api.updateSettings(body);
      setDisplayDefaults(body.display);
      // If this page's own address stopped being served, follow the
      // console to where it now is.
      const next = consoleUrlAfter(body.web);
      if (next) {
        notice = `Settings saved. The console has moved: opening ${next} …`;
        setTimeout(() => (window.location.href = next), 1500);
        return;
      }
      notice = 'Settings saved and applied.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  // Where this page should go after a web access change, or null if its
  // current address still works. A port in the URL that matches the new
  // settings is kept; the host name always is.
  function consoleUrlAfter(web) {
    const here = window.location;
    const port = Number(here.port) || (here.protocol === 'https:' ? 443 : 80);
    const path = here.pathname + here.search + here.hash;
    // location.hostname keeps the brackets of an IPv6 literal ([::1]).
    const host = here.hostname.includes(':') && !here.hostname.startsWith('[') ? `[${here.hostname}]` : here.hostname;
    const url = (scheme, p) => `${scheme}://${host}${(scheme === 'https' && p === 443) || (scheme === 'http' && p === 80) ? '' : `:${p}`}${path}`;
    const servesHttp = web.http_enabled && !web.redirect_http && port === web.http_port;
    const servesHttps = web.https_enabled && port === web.https_port;
    if (here.protocol === 'http:' && servesHttp) return null;
    if (here.protocol === 'https:' && servesHttps) return null;
    if (web.https_enabled) return url('https', web.https_port);
    return url('http', web.http_port);
  }

  // Auto-block category picker: checked state lives in aiCategoriesText so
  // both the picker and (fallback) text field share one source of truth.
  function aiSelectedCategories() {
    return (aiCategoriesText || '')
      .split(',')
      .map((c) => c.trim().toLowerCase())
      .filter(Boolean);
  }

  function toggleAiCategory(cat) {
    const sel = aiSelectedCategories();
    const next = sel.includes(cat) ? sel.filter((c) => c !== cat) : [...sel, cat];
    aiCategoriesText = next.join(', ');
  }

  // 4.999999 -> 5 (unit conversions in the AI form).
  function round2(n) {
    return Math.round(Number(n || 0) * 100) / 100;
  }

  function titleCase(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }
</script>

<PageHeader icon={icons.settings} title="Settings" tagline={TAGLINES[tab]} />

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

  {#if tab !== 'backup'}
  <div class="actions" class:dirty>
    <button onclick={save} disabled={busy || !dirty}>{busy ? 'Saving…' : 'Save Changes'}</button>
    <button class="secondary" onclick={reload} disabled={busy}>{dirty ? 'Discard Changes' : 'Reload'}</button>
    {#if dirty}<span class="unsaved">Unsaved changes (Save covers every tab)</span>{/if}
  </div>
  {/if}

  {#if tab === 'general'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Web Console Access</h3>
    <div class="access">
      <div class="access-row">
        <label class="check"><input type="checkbox" bind:checked={web_.http_enabled} /> <span>HTTP</span></label>
        <label><span>Port</span><input type="number" min="1" max="65535" bind:value={web_.http_port} disabled={!web_.http_enabled} /></label>
        <label class="check"><input type="checkbox" bind:checked={web_.redirect_http} disabled={!web_.http_enabled || !web_.https_enabled} /> <span>Redirect to HTTPS</span></label>
      </div>
      <div class="access-row">
        <label class="check"><input type="checkbox" bind:checked={web_.https_enabled} /> <span>HTTPS</span></label>
        <label><span>Port</span><input type="number" min="1" max="65535" bind:value={web_.https_port} disabled={!web_.https_enabled} /></label>
        <label><span>Certificate</span>
          <select bind:value={web_.https_certificate} disabled={!web_.https_enabled}>
            <option value="">Self-Signed (Generated Automatically)</option>
            {#each certs.filter((c) => c.name !== 'web-console' || web_.https_certificate !== '') as cert (cert.name)}
              <option value={cert.name}>{cert.name === 'web-console' ? 'web-console - Self-Signed' : certLabel(cert)}</option>
            {/each}
          </select>
        </label>
      </div>
    </div>
    {#if !web_.http_enabled && !web_.https_enabled}
      <p class="help restart">Turn on HTTP, HTTPS or both, or the console cannot be reached.</p>
    {:else if consoleUrlAfter({ ...web_, http_port: Number(web_.http_port), https_port: Number(web_.https_port), redirect_http: web_.redirect_http && web_.http_enabled && web_.https_enabled })}
      <p class="help restart">
        After saving, this page moves to
        <strong>{consoleUrlAfter({ ...web_, http_port: Number(web_.http_port), https_port: Number(web_.https_port), redirect_http: web_.redirect_http && web_.http_enabled && web_.https_enabled })}</strong>.
      </p>
    {/if}
    <p class="muted help">
      Upload a certificate for this server's name on the Certificates page
      to use one browsers trust; the self-signed one makes browsers show a
      warning until you accept it. A change applies straight away: new ports
      are opened before old ones close, and a change that cannot work
      (a port in use, a certificate that does not load) is refused. If you
      lock yourself out anyway, run <code>daygle-dns reset-web-access</code>
      on the server and restart it to get plain HTTP back on port
      {config?.api?.port}.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS Listeners</h3>
    <table class="facts">
      <tbody>
        <tr><th>Listen Address</th><td>{listenMeaning(server.listen, server.ipv6_only)} <span class="muted">({server.listen})</span></td></tr>
        <tr><th>Port</th><td>{server.port}</td></tr>
        <tr><th>UDP</th><td><span class="pill" class:ok={server.udp_enabled}>{server.udp_enabled ? 'On' : 'Off'}</span></td></tr>
        <tr><th>TCP</th><td><span class="pill" class:ok={server.tcp_enabled}>{server.tcp_enabled ? 'On' : 'Off'}</span></td></tr>
        <tr><th>Reload Config File on Change</th><td><span class="pill" class:ok={server.reload_enabled}>{server.reload_enabled ? 'On' : 'Off'}</span></td></tr>
      </tbody>
    </table>
    <p class="muted help">
      To change these, edit the <code>[server]</code> section of
      <code>daygle-dns.toml</code> and restart (or let Reload Config File
      pick it up). Use <code>0.0.0.0</code> for IPv4 only, <code>::</code>
      for IPv4 and IPv6, or <code>::</code> with <code>ipv6_only = true</code>
      for IPv6 only. To listen on particular addresses, list them separated
      by commas, for example <code>192.168.1.2, fd00::53</code>. They live in the file rather than here so a listener that
      stops working can always be fixed without the console. The web console
      listens on {config?.api?.listen}. DNS over TLS, HTTPS and QUIC are on
      the Encrypted DNS tab.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Remote Logging (Syslog)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={syslog_.enabled} /> <span>Send Logs to a Syslog Server</span></label>
      <label>
        <span>Syslog Server</span>
        <input placeholder="logs.example.com or tcp://10.0.0.5:6514" bind:value={syslog_.server} disabled={!syslog_.enabled} spellcheck="false" />
      </label>
      <label>
        <span>Facility</span>
        <select bind:value={syslog_.facility} disabled={!syslog_.enabled}>
          <option value="daemon">daemon</option>
          <option value="user">user</option>
          {#each [0, 1, 2, 3, 4, 5, 6, 7] as n (n)}<option value={`local${n}`}>local{n}</option>{/each}
        </select>
      </label>
      <label>
        <span>Server Log Messages</span>
        <select bind:value={syslog_.level} disabled={!syslog_.enabled}>
          <option value="info">Information and Above</option>
          <option value="warn">Warnings and Errors</option>
          <option value="error">Errors Only</option>
        </select>
      </label>
      <label class="check"><input type="checkbox" bind:checked={syslog_.queries} disabled={!syslog_.enabled} /> <span>Also Send Every Query</span></label>
    </div>
    <p class="muted help">
      Sends the server log (and, if chosen, a line per query) as RFC 5424
      syslog, over UDP by default (port 514), or TCP with
      <code>tcp://host:port</code>. Changes apply as soon as they are saved.
      Every query can be a lot of traffic on a busy server.
    </p>
  </div>
  {:else if tab === 'recursive'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Resolver</h3>
    <div class="form-grid">
      <label>
        <span>Resolution Mode</span>
        <select bind:value={recursive.mode}>
          <option value="recursive">Recursive (from the root servers)</option>
          <option value="forwarding">Forwarding (to upstream servers)</option>
        </select>
      </label>
      <label class="check"><input type="checkbox" bind:checked={recursive.enabled} /> <span>Recursion Enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={recursive.dnssec_validate} disabled={!recursive.enabled} /> <span>DNSSEC Validation</span></label>
    </div>
    {#if !recursive.enabled}
      <p class="help restart">
        Recursion is off: the server answers only for its own zones and
        refuses everything else.
      </p>
    {:else if recursive.mode === 'recursive'}
      <div class="form-grid" style="margin-top: 4px">
        <label class="check"><input type="checkbox" bind:checked={recursive.case_randomization} /> <span>Randomize Query Case (0x20)</span></label>
        <label class="check"><input type="checkbox" bind:checked={recursive.rebinding_protection} /> <span>DNS Rebinding Protection</span></label>
        <label class="check"><input type="checkbox" bind:checked={recursive.opportunistic_encryption} /> <span>Opportunistic Encryption</span></label>
      </div>
      <p class="muted help">
        Daygle DNS resolves names itself, starting at the root servers, so no upstream
        provider sees your queries. Query names are minimized (RFC 9156) and DNSSEC
        is validated against the root trust anchor. Query-case randomization makes
        spoofed answers harder to inject but can fail with the odd server that does
        not preserve case. Rebinding protection drops private and loopback addresses
        from public answers (your own zones, forwarders and stub zones are not
        affected). Opportunistic encryption (RFC 9539) probes nameservers for DNS
        over TLS or QUIC in the background and uses it where it works, falling back
        to plain DNS; it is experimental and adds some connection overhead.
      </p>
    {:else}
      <div class="form-grid" style="margin-top: 4px">
        <label class="check"><input type="checkbox" bind:checked={recursive.use_system_config} /> <span>Use System DNS Configuration</span></label>
      </div>
      <label class="stacked" style="margin-top: 12px">
        <span>Upstream Servers (one per line)</span>
        <textarea rows="4" bind:value={upstreamText} placeholder={'1.1.1.1\n9.9.9.9:53\ntls://1.1.1.1:853@cloudflare-dns.com\nhttps://dns.quad9.net/dns-query'}></textarea>
      </label>
      <p class="muted help">
        Queries are sent to these upstream servers, or to the system's resolver when
        the list is empty or Use System DNS Configuration is set.
      </p>
    {/if}
    {#if recursive.enabled}
      <h4>Outbound IP Versions</h4>
      <div class="form-grid">
        <label>
          <span>Send Queries Over</span>
          <select bind:value={recursive.outbound_ip_versions}>
            <option value="both">IPv4 and IPv6</option>
            <option value="ipv4">IPv4 Only</option>
            <option value="ipv6">IPv6 Only</option>
          </select>
        </label>
      </div>
      <p class="muted help">
        Which IP versions this server uses for its own lookups: root and domain
        name servers, upstream servers, conditional forwarders, stub zones and the
        root zone download. Choose IPv4 Only when this host has an IPv6 address
        but IPv6 does not reach the internet, which otherwise shows up as slow or
        failing lookups. Servers of the other version are skipped, and a list
        left with none is refused. This does not change what clients can ask
        for: IPv6 (AAAA) records are still resolved and served.
      </p>
    {/if}
    <h4>Recursion Access</h4>
    <div class="form-grid">
      <label>
        <span>Who May Use Recursion</span>
        <select bind:value={recursive.recursion_access}>
          <option value="private_networks">Private Networks Only</option>
          <option value="allow">Everyone</option>
          <option value="custom">Custom Networks</option>
          <option value="deny">Nobody</option>
        </select>
      </label>
    </div>
    {#if recursive.recursion_access === 'custom'}
      <label class="stacked" style="margin-top: 12px">
        <span>Allowed Networks (one per line, e.g. 192.168.1.0/24 or a single IP)</span>
        <textarea rows="3" placeholder={'192.168.1.0/24\n2001:db8::/48'} bind:value={recursionNetworksText}></textarea>
      </label>
    {/if}
    <p class="muted help">
      Applies to everything this server resolves rather than answers from its own
      zones; refused clients get REFUSED. Private Networks Only covers loopback,
      10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT), link-local, IPv6 ULA and
      the IPv6 networks this server is on (most LANs give devices addresses from
      the ISP's prefix rather than ULA), so the server is not an open resolver
      if it is reachable from the internet.
      Your own zones are answered for everyone.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS64 (RFC 6147)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={dns64.enabled} /> <span>Make IPv6 Answers for IPv4-Only Names</span></label>
      <label><span>NAT64 Prefix</span><input placeholder="64:ff9b::/96" bind:value={dns64.prefix} disabled={!dns64.enabled} spellcheck="false" /></label>
    </div>
    <label class="stacked" style="margin-top: 12px">
      <span>Clients (one network per line; empty means every client)</span>
      <textarea rows="2" placeholder={'2001:db8:1::/48'} bind:value={dns64ClientsText} disabled={!dns64.enabled}></textarea>
    </label>
    <p class="muted help">
      For IPv6-only networks with a NAT64 gateway: when a name has no IPv6
      address, its IPv4 addresses are answered as IPv6 addresses inside the
      gateway's prefix, so IPv6-only devices can still reach it. Use your
      gateway's prefix (/32, /40, /48, /56, /64 or /96); the well-known
      64:ff9b::/96 only carries public IPv4 addresses. Clients that validate
      DNSSEC themselves get the real answer. Only turn this on for networks
      behind NAT64: elsewhere the made-up addresses lead nowhere.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">EDNS Client Subnet (RFC 7871)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={ecs.enabled} /> <span>Tell Upstreams Where Queries Come From</span></label>
      <label><span>Send This Network for Everyone</span><input placeholder="Each client's own network" bind:value={ecs.subnet} disabled={!ecs.enabled} spellcheck="false" /></label>
      <label><span>IPv4 Bits Sent per Client</span><input type="number" min="1" max="32" bind:value={ecs.ipv4_prefix} disabled={!ecs.enabled || !!ecs.subnet.trim()} /></label>
      <label><span>IPv6 Bits Sent per Client</span><input type="number" min="1" max="128" bind:value={ecs.ipv6_prefix} disabled={!ecs.enabled || !!ecs.subnet.trim()} /></label>
    </div>
    <p class="muted help">
      CDNs pick the server nearest the network a query comes from. When this
      server forwards to a distant upstream, sending the network lets them pick
      one near your clients instead. Set your site's public network (e.g.
      203.0.113.0/24) to send it for every query; leave it empty to send each
      client's own public network, cut to the bits above (private addresses are
      never sent). Only forwarding upstreams get it, not the root and TLD
      servers. The cache is shared, so per-client networks are best when clients
      are near each other.
    </p>
  </div>
  <ClientPolicies />
  {:else if tab === 'cache'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Cache Lifetimes</h3>
    <div class="recursive-cache-grid">
      <label><span>Minimum Cache TTL (Seconds)</span><span class="hint">{hint(recursive.min_cache_ttl)}</span><input type="number" min="0" bind:value={recursive.min_cache_ttl} /></label>
      <label><span>Negative Cache TTL (Seconds)</span><span class="hint">{hint(recursive.negative_cache_ttl)}</span><input type="number" min="0" bind:value={recursive.negative_cache_ttl} /></label>
      <label><span>Maximum Cache TTL (Seconds)</span><span class="hint">{hint(recursive.max_cache_ttl)}</span><input type="number" min="0" bind:value={recursive.max_cache_ttl} /></label>
      <label><span>Failure Cache TTL (Seconds)</span><span class="hint">{hint(recursive.failure_cache_ttl)}</span><input type="number" min="0" bind:value={recursive.failure_cache_ttl} /></label>
      <label><span>Cache Size (Entries)</span><input type="number" min="0" bind:value={recursive.cache_size} /></label>
    </div>
    <p class="muted help">
      Minimum and negative TTLs bound how long records stay in cache. Maximum TTL
      clamps positive answers at insert time so tracking-heavy domains cannot pin
      themselves in cache for weeks. Failure Cache TTL caches SERVFAIL and other
      upstream errors briefly so a broken upstream is not hammered on every query;
      set it to 0 to disable.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Refreshing and Stale Answers</h3>
    <div class="recursive-cache-grid">
      <label class="check"><input type="checkbox" bind:checked={recursive.prefetch_enabled} /> <span>Refresh Popular Names Early</span></label>
      <label><span>Refresh When TTL Left Is Below (%)</span><input type="number" min="1" max="99" bind:value={recursive.prefetch_ttl_fraction_pct} disabled={!recursive.prefetch_enabled} /></label>
      <label><span>Refresh Names Queried At Least (Times)</span><input type="number" min="1" bind:value={recursive.prefetch_min_queries} disabled={!recursive.prefetch_enabled} /></label>
      <label><span>Serve-Stale Window (Seconds)</span><span class="hint">{hint(recursive.serve_stale_secs)}</span><input type="number" min="0" bind:value={recursive.serve_stale_secs} /></label>
    </div>
    <p class="muted help">
      Refreshing popular names early re-fetches a name before it expires once
      it has been asked for often enough, so clients rarely wait. Serve-stale
      answers from an expired entry for this long when the upstream cannot be
      reached. The Cache page shows hit rates and can flush the cache.
    </p>
  </div>
  {:else if tab === 'zones'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Zone Defaults</h3>
    <div class="form-grid top">
      <label><span>Default Record TTL (Seconds)</span><span class="hint">{hint(authoritative.default_record_ttl)}</span><input type="number" min="1" bind:value={authoritative.default_record_ttl} /></label>
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
    <h3 style="margin: 0 0 10px">Zone Transfers (AXFR/IXFR)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={authoritative.axfr_enabled} /> <span>Allow Zone Transfers</span></label>
    </div>
    <label class="stacked">
      <span>Allowed Networks (one CIDR per line, e.g. 192.168.1.0/24)</span>
      <textarea rows="3" placeholder={"192.168.1.0/24\n10.0.0.0/8"} bind:value={axfrNetworksText}></textarea>
    </label>
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
    <label class="stacked">
      <span>Allowed Networks (one CIDR per line)</span>
      <textarea rows="3" placeholder={"192.168.1.0/24\n10.0.0.0/8"} bind:value={updateNetworksText}></textarea>
    </label>
    <p class="muted help">
      Clients on these networks may add, change, or delete records in primary
      zones with UPDATE messages. An empty list allows every client when
      dynamic updates are enabled. Applies immediately, no restart needed.
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
  {:else if tab === 'listeners'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS over TLS</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={dot.enabled} /> <span>Enabled</span></label>
      <label><span>Port</span><input type="number" bind:value={dot.port} /></label>
      <label><span>Handshake Timeout (Seconds)</span><input type="number" min="1" bind:value={dot.handshake_timeout_secs} /></label>
      <label>
        <span>Certificate</span>
        <select bind:value={dotCertMode} onchange={(e) => applyCertMode(dot, e.currentTarget.value)}>
          <option value="self">Self-Signed (Generated Automatically)</option>
          {#each certs as cert (cert.name)}
            <option value={cert.name}>{certLabel(cert)}</option>
          {/each}
          <option value="custom">Certificate Files on the Server…</option>
        </select>
      </label>
      {#if dotCertMode === 'self'}
        <label><span>Server Name</span><input bind:value={dot.server_name} placeholder="dns.example.com" /></label>
      {:else if dotCertMode === 'custom'}
        <label><span>Certificate Path</span><input bind:value={dot.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
        <label><span>Key Path</span><input bind:value={dot.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
      {/if}
    </div>
    <p class="muted help">Clients connect to port {dot.port || 853} (the standard port is 853).</p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS over HTTPS</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={doh.enabled} /> <span>Enabled</span></label>
      <label><span>Port</span><input type="number" bind:value={doh.port} /></label>
      <label><span>Handshake Timeout (Seconds)</span><input type="number" min="1" bind:value={doh.handshake_timeout_secs} /></label>
      <label>
        <span>Certificate</span>
        <select bind:value={dohCertMode} onchange={(e) => applyCertMode(doh, e.currentTarget.value)}>
          <option value="self">Self-Signed (Generated Automatically)</option>
          {#each certs as cert (cert.name)}
            <option value={cert.name}>{certLabel(cert)}</option>
          {/each}
          <option value="custom">Certificate Files on the Server…</option>
        </select>
      </label>
      {#if dohCertMode === 'self'}
        <label><span>Server Name</span><input bind:value={doh.server_name} placeholder="dns.example.com" /></label>
      {:else if dohCertMode === 'custom'}
        <label><span>Certificate Path</span><input bind:value={doh.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
        <label><span>Key Path</span><input bind:value={doh.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
      {/if}
      <label><span>Endpoint Path</span><input bind:value={doh.endpoint} placeholder="/dns-query" /></label>
    </div>
    <p class="muted help">Clients use <code>https://{doh.server_name || 'this-server'}{Number(doh.port) === 443 ? '' : `:${doh.port}`}{doh.endpoint || '/dns-query'}</code>. The standard port is 443.</p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS over QUIC</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={doq.enabled} /> <span>Enabled</span></label>
      <label><span>Port</span><input type="number" bind:value={doq.port} /></label>
      <label>
        <span>Certificate</span>
        <select bind:value={doqCertMode} onchange={(e) => applyCertMode(doq, e.currentTarget.value)}>
          <option value="self">Self-Signed (Generated Automatically)</option>
          {#each certs as cert (cert.name)}
            <option value={cert.name}>{certLabel(cert)}</option>
          {/each}
          <option value="custom">Certificate Files on the Server…</option>
        </select>
      </label>
      {#if doqCertMode === 'self'}
        <label><span>Server Name</span><input bind:value={doq.server_name} placeholder="dns.example.com" /></label>
      {:else if doqCertMode === 'custom'}
        <label><span>Certificate Path</span><input bind:value={doq.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
        <label><span>Key Path</span><input bind:value={doq.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
      {/if}
    </div>
    <p class="muted help">
      Clients connect to UDP port {doq.port || 853} (the standard port is 853).
      Manage certificates, and see when they expire, on the Certificates page.
    </p>
  </div>
  {:else if tab === 'ai'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">AI Safety Scanner</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={ai_.enabled} /> <span>Enable AI Scanner</span></label>
      <label>
        <span>Mode</span>
        <select bind:value={ai_.mode}>
          <option value="train">Train - Record Verdicts Only</option>
          <option value="enforce">Enforce - Auto-Block Qualifying Domains</option>
        </select>
      </label>
    </div>
    {#if ai_.enabled && !aiRunning}
      <p class="help restart">The scanner starts after the next restart.</p>
    {/if}
    <p class="muted help">
      Classifies the domains seen in your DNS traffic in the background, never
      on the query path. Start in Train mode and review the verdicts on the AI
      page before switching to Enforce. Your allowlist and the AI page's exempt
      domains are never blocked.
    </p>

    <h4>Scanning</h4>
    <div class="form-grid">
      <label><span>Scan Every (Minutes)</span><input type="number" min="0.17" step="any" bind:value={aiForm.scanMinutes} /></label>
      <label><span>Domains Classified Per Scan</span><input type="number" min="1" bind:value={ai_.max_domains_per_scan} /></label>
      <label><span>Classification Workers</span><input type="number" min="1" max="32" bind:value={ai_.workers} /></label>
    </div>
    <p class="muted help">
      Each scan picks up the domains queried since the previous one and
      classifies up to the per-scan limit (the rest wait for the next scan),
      on this many background threads.
    </p>

    <h4>Enforcement</h4>
    <div class="form-grid">
      <label><span>Block Threshold (%)</span><input type="number" min="50" max="100" step="any" bind:value={aiForm.thresholdPct} /></label>
      <label><span>Confidence Floor (%)</span><input type="number" min="0" max="99" step="any" bind:value={aiForm.floorPct} /></label>
    </div>
    <div class="stacked" style="margin-top: 12px">
      <span class="field-label">Auto-Block Categories</span>
      {#if aiBackendCategories.length}
        <div class="category-grid">
          {#each aiBackendCategories as cat (cat)}
            <label class="check">
              <input
                type="checkbox"
                checked={aiSelectedCategories().includes(cat)}
                onchange={() => toggleAiCategory(cat)}
              />
              <span>{titleCase(cat)}</span>
            </label>
          {/each}
        </div>
      {:else}
        <input bind:value={aiCategoriesText} placeholder="malware, phishing (comma-separated)" />
      {/if}
    </div>
    <p class="muted help">
      In Enforce mode a domain is blocked when its current verdict is in a
      ticked category with a confidence at or above the block threshold (50 to
      100%). Verdicts below the confidence floor are recorded as skipped.
    </p>

    <h4>Verdict Lifetime</h4>
    <div class="form-grid">
      <label><span>Re-Check Threat Verdicts After (Days)</span><input type="number" min="0.01" step="any" bind:value={aiForm.threatDays} /></label>
      <label><span>Re-Check Other Verdicts After (Days)</span><input type="number" min="0.01" step="any" bind:value={aiForm.categoryDays} /></label>
      <label><span>Look for Expired Verdicts Every (Minutes)</span><input type="number" min="0.17" step="any" bind:value={aiForm.expireMinutes} /></label>
    </div>
    <p class="muted help">
      Sites change, so verdicts expire and the domain is classified again;
      an expired verdict stops blocking until then. Threats (malware, phishing)
      are re-checked sooner than other categories.
    </p>
  </div>
  {:else if tab === 'interface'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Date & Time Defaults</h3>
    <div class="form-grid">
      <label><span>Time Zone</span>
        <select bind:value={display_.time_zone}>
          {#each zoneChoices as [value, label]}<option value={value}>{label}</option>{/each}
        </select>
      </label>
      <label><span>Date Format</span>
        <select bind:value={display_.date_format}>
          {#each DATE_FORMAT_OPTIONS as [value, label]}<option value={value}>{label}</option>{/each}
        </select>
      </label>
      <label><span>Time Format</span>
        <select bind:value={display_.time_format}>
          {#each TIME_FORMAT_OPTIONS as [value, label]}<option value={value}>{label}</option>{/each}
        </select>
      </label>
    </div>
    <p class="muted help">
      Example: <strong>{previewDateTime(display_)}</strong>. These are the
      defaults for every user. Each user can choose their own under
      the Preferences tab of their <strong>Account</strong> page.
      {#if ownPrefsSet}Your own preferences are set, so you won't see a change
        here until you reset them.{/if}
      "Device Time Zone" and "Browser Default" follow each viewer's computer.
    </p>
  </div>
  {:else if tab === 'backup'}
  <BackupRestore />
  {/if}
{:else}
  <div class="card">
    <p class="muted">Loading…</p>
  </div>
{/if}

<style>
  .actions { display: flex; gap: 10px; margin-bottom: 16px; }
  .stacked {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 4px;
  }
  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
    align-items: end;
  }
  .recursive-cache-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    align-items: start;
  }
  /* Two lines for every label, so the inputs line up whether or not a
     label wraps or a duration hint follows the field. */
  .recursive-cache-grid label:not(.check) > span:first-child { min-height: 2.6em; display: flex; align-items: flex-end; }
  .recursive-cache-grid label.check { padding-top: 2.6em; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  label.check {
    flex-direction: row;
    align-items: center;
    gap: 8px;
    padding-bottom: 8px;
  }
  label.check span { color: var(--text); }
  h4 { margin: 14px 0 8px; }
  .field-label { font-size: 0.85rem; color: var(--muted); }
  .category-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 4px 12px;
    margin-top: 6px;
  }
  .help.restart { color: #f5b041; margin-top: 8px; }
  /* Save bar: stays in view while scrolling a long tab. */
  .actions {
    position: sticky;
    top: 0;
    z-index: 5;
    align-items: center;
    padding: 10px 0;
    background: var(--bg);
  }
  .unsaved { color: #f5b041; font-size: 0.85rem; }
  .form-grid.top { align-items: start; }
  .access { display: flex; flex-direction: column; gap: 10px; }
  .access-row { display: grid; grid-template-columns: 110px 140px minmax(0, 1fr); gap: 12px; align-items: end; }
  .access-row label.check { padding-bottom: 8px; }
  @media (max-width: 640px) {
    .access-row { grid-template-columns: 1fr 1fr; }
  }
  /* Below the field, so it never collides with a label that wraps. */
  .hint { order: 3; font-size: 0.72rem; color: var(--muted); min-height: 1em; }
  .facts { width: auto; }
  .facts th { text-align: left; padding-right: 24px; color: var(--muted); font-weight: 500; }
</style>

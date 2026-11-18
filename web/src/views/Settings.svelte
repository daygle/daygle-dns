<script>
  import { untrack } from 'svelte';
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import BackupRestore from './BackupRestore.svelte';
  import NetworkPicker from '../NetworkPicker.svelte';
  import { icons } from '../icons.svelte.js';
  import { display, setDisplayDefaults, timeZoneOptions, DATE_FORMAT_OPTIONS, TIME_FORMAT_OPTIONS, previewDateTime, formatDateTime } from '../datetime.svelte.js';
  import { THEME_OPTIONS } from '../theme.svelte.js';

  let config = $state(null);
  let notice = $state(null);
  let error = $state(null);
  let busy = $state(false);

  // Server-wide settings, split into tabs (same pattern as the Logs page).
  // A feature's own settings live on its page instead (AI, Zones, Cache and
  // DHCP each have a Settings tab), saved separately from this form.
  // `initialTab` lets another page open a tab directly (the Certificates
  // page's buttons, Reports' scheduled-report link).
  let { initialTab = 'general' } = $props();
  let tab = $state(untrack(() => initialTab));
  const TABS = [
    ['general', 'General'],
    ['listeners', 'DNS Listeners'],
    ['recursive', 'Resolver'],
    ['rate-limiting', 'Rate Limiting'],
    ['logging', 'Logging'],
    ['alerts', 'Notifications'],
    ['backup', 'Backup'],
  ];
  const TAGLINES = {
    general: 'How the web console is reached (HTTP, HTTPS or both), and how dates, times and colours are shown by default.',
    listeners: 'Where clients reach this server: plain DNS over UDP and TCP, encrypted DNS over TLS, HTTPS and QUIC with the certificate each one presents, and advertising them to devices.',
    recursive: 'How the server answers names it does not host: resolving them itself from the root servers or forwarding to upstreams, how long it waits, and DNS64 and client subnet options. Who may use it is under Clients → Access.',
    logging: 'How long the query log is kept, optional daily log files, and sending the server log and queries to a syslog server or a log collector over HTTP. The logs themselves are on the Logs page.',
    'rate-limiting': 'Per-client and per-domain query limits, and response rate limiting (RRL), which stops this server being used to flood someone else with DNS answers sent to a forged address.',
    alerts: 'Where notifications go (webhook, email or both), the alerts sent when something needs attention, and a scheduled summary report.',
    backup: 'Download a backup of everything this server keeps, or restore one.',
  };

  // Local editable copies (bound to the form inputs).
  let server = $state({});
  let recursive = $state({});
  let dot = $state({});
  let doh = $state({});
  let doq = $state({});
  let api_ = $state({});
  let upstreamText = $state('');
  // Root server addresses, one per line (empty: the built-in IANA roots).
  let rootHintsText = $state('');
  // Per-client and per-domain query limits (`[rate_limit]`).
  let rateLimit_ = $state({});
  // Named networks (Clients -> Networks) for the pickers below.
  let networks = $state([]);
  // Encrypted-listener client networks (Settings -> DNS Listeners).
  let dotNetworks = $state([]);
  let dohNetworks = $state([]);
  let doqNetworks = $state([]);

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

  // Server-wide date, time and theme display defaults (saved with the page).
  let display_ = $state({ time_zone: 'system', date_format: 'system', time_format: 'system', theme: 'light' });
  // How the web console is served (Settings -> General). `http_port` 0 in
  // the stored settings means the config file's api.port; the form shows
  // the real number.
  let web_ = $state({ http_enabled: true, http_port: 5380, https_enabled: false, https_port: 5443, https_certificate: '', redirect_http: false });
  // DNS64 and ECS (Resolver tab), remote logging (Logging tab).
  let dns64 = $state({ enabled: false, prefix: '64:ff9b::/96' });
  let dns64Clients = $state([]);
  let ecs = $state({ enabled: false, subnet: '', ipv4_prefix: 24, ipv6_prefix: 56 });
  let syslog_ = $state({ enabled: false, server: '', facility: 'daemon', level: 'info', queries: false });
  const EXPORT_DEFAULTS = { enabled: false, url: '', format: 'ndjson', authorization: '', batch_size: 500, flush_secs: 5 };
  let export_ = $state({ ...EXPORT_DEFAULTS });
  let exportStatus = $state(null);
  let exportTest = $state(null);
  let exportTesting = $state(false);
  // dnstap: every query and its response, streamed to a collector.
  const DNSTAP_DEFAULTS = { enabled: false, server: '', identity: '', version: '' };
  let dnstap_ = $state({ ...DNSTAP_DEFAULTS });
  let dnstapTest = $state(null);
  let dnstapTesting = $state(false);
  // Query log storage and retention (Logging tab), and how big it is now.
  const LOGGING_DEFAULTS = {
    query_db_enabled: true,
    query_db_max_rows: 200000,
    query_db_retention_days: 0,
    query_log_enabled: false,
    query_log_dir: '/var/log/daygle-dns',
    query_log_retention_days: 30,
  };
  let logging_ = $state({ ...LOGGING_DEFAULTS });
  let queryLogStats = $state(null);
  // Age limits offered for the query log (0: none); a configured value
  // outside these is kept as its own option.
  const KEEP_DAYS = [0, 7, 14, 30, 60, 90, 180, 365];
  $effect(() => {
    if (tab !== 'logging') return;
    api.logExportStatus().then((s) => { exportStatus = s; }).catch(() => {});
    api.queryLogStats().then((s) => { queryLogStats = s; }).catch(() => {});
  });
  function fmtBytes(n) {
    if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
    if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${Math.round(n / 1024)} KB`;
  }

  function exportBody() {
    return {
      enabled: !!export_.enabled,
      url: (export_.url || '').trim(),
      format: export_.format || 'ndjson',
      authorization: (export_.authorization || '').trim(),
      batch_size: Number(export_.batch_size),
      flush_secs: Number(export_.flush_secs),
    };
  }

  async function testExport() {
    exportTesting = true;
    exportTest = null;
    try {
      await api.testLogExport(exportBody());
      exportTest = { ok: true, msg: 'Test query sent and accepted.' };
    } catch (e) {
      exportTest = { ok: false, msg: formatApiError(e) };
    } finally {
      exportTesting = false;
    }
  }
  function dnstapBody() {
    return {
      enabled: !!dnstap_.enabled,
      server: (dnstap_.server || '').trim(),
      identity: (dnstap_.identity || '').trim(),
      version: (dnstap_.version || '').trim(),
    };
  }

  // Connects, completes the Frame Streams handshake and sends one sample
  // event, so a collector can be checked before the form is saved.
  async function testDnstap() {
    dnstapTesting = true;
    dnstapTest = null;
    try {
      await api.testDnstap(dnstapBody());
      dnstapTest = { ok: true, msg: 'Collector accepted the sample event.' };
    } catch (e) {
      dnstapTest = { ok: false, msg: formatApiError(e) };
    } finally {
      dnstapTesting = false;
    }
  }
  const ALERT_DEFAULTS = {
    enabled: false, webhook_url: '', smtp_server: '', smtp_port: 587, smtp_security: 'starttls',
    smtp_username: '', smtp_password: '', email_from: '', email_to: [],
    blocklist_failures: true, zone_transfer_failures: true, certificate_expiry: true,
    dnssec: true, update_available: true, update_failure: true, ai_blocks: false,
    ai_model: true,
  };
  const ALERT_EVENTS = [
    ['blocklist_failures', 'A blocklist cannot be downloaded'],
    ['zone_transfer_failures', 'A secondary zone cannot be refreshed from its primary'],
    ['certificate_expiry', 'A certificate expires within 14 days, or cannot be renewed'],
    ['dnssec', 'DNSSEC: a key rollover needs a new DS record, or signing fails'],
    ['update_available', 'A new Daygle DNS release is available'],
    ['update_failure', 'An automatic stable-release installation fails'],
    ['ai_blocks', 'The AI starts blocking new domains (Enforce mode)'],
    ['ai_model', 'The AI rejects a model it retrained (its shadow trial went badly)'],
  ];
  let alerts_ = $state({ ...ALERT_DEFAULTS });
  const RRL_DEFAULTS = {
    enabled: false, responses_per_second: 10, nxdomains_per_second: 10, errors_per_second: 10,
    window_secs: 15, slip: 2, ipv4_prefix: 24, ipv6_prefix: 56, log_only: false,
  };
  let rrl_ = $state({ ...RRL_DEFAULTS });
  let ddr_ = $state({ enabled: true, name: '' });
  const REPORT_DEFAULTS = { enabled: false, frequency: 'weekly', weekday: 'mon', hour: 8, top: 10 };
  let reports_ = $state({ ...REPORT_DEFAULTS });
  let reportSending = $state(false);
  let reportResult = $state(null);

  function reportsBody() {
    return {
      enabled: !!reports_.enabled,
      frequency: reports_.frequency,
      weekday: reports_.weekday,
      hour: Number(reports_.hour),
      top: Number(reports_.top),
    };
  }

  async function sendReportNow() {
    reportSending = true;
    reportResult = null;
    try {
      await api.sendReport(reportsBody());
      reportResult = { ok: true, msg: 'Report sent. Check that it arrived.' };
    } catch (e) {
      reportResult = { ok: false, msg: formatApiError(e) };
    } finally {
      reportSending = false;
    }
  }
  let rrlExempt = $state([]);
  // RRL counters since start (from /api/metrics), shown on its tab.
  let rrlCounts = $state(null);
  $effect(() => {
    if (tab !== 'rate-limiting') return;
    api.metrics().then((m) => { rrlCounts = m; }).catch(() => {});
  });
  // Recipients as typed (one per line or comma-separated).
  let alertTo = $state('');
  let alertTest = $state(null);
  let alertTesting = $state(false);

  function alertsBody() {
    return {
      ...alerts_,
      smtp_port: Number(alerts_.smtp_port),
      webhook_url: (alerts_.webhook_url || '').trim(),
      smtp_server: (alerts_.smtp_server || '').trim(),
      smtp_username: (alerts_.smtp_username || '').trim(),
      email_from: (alerts_.email_from || '').trim(),
      email_to: alertTo.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
    };
  }

  async function testAlert() {
    alertTesting = true;
    alertTest = null;
    try {
      await api.testAlert(alertsBody());
      alertTest = { ok: true, msg: 'Test alert sent. Check that it arrived.' };
    } catch (e) {
      alertTest = { ok: false, msg: formatApiError(e) };
    } finally {
      alertTesting = false;
    }
  }
  const zoneChoices = timeZoneOptions();
  // Users who chose their own settings don't see the defaults change.
  const ownPrefsSet = $derived(
    !!(display.mine && (display.mine.time_zone || display.mine.date_format || display.mine.time_format || display.mine.theme)),
  );

  $effect(() => {
    load();
    api.certificates().then((list) => { certs = list || []; }).catch(() => {});
  });

  // A managed certificate in the picker, flagged when it is not usable.
  function certLabel(cert) {
    const names = (cert.names || []).filter((n) => n !== 'localhost');
    let label = names.length ? `${cert.name} - ${names[0]}` : cert.server_name ? `${cert.name} - ${cert.server_name}` : cert.name;
    if (cert.not_after && Date.parse(cert.not_after) <= Date.now()) label += ' (Expired)';
    return label;
  }

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
    api.networks().then((data) => { networks = data.networks || []; }).catch(() => {});
    try {
      config = await api.config();
      if (config == null) {
        server = {};
        recursive = {};
        dot = {};
        doh = {};
        doq = {};
        api_ = {};
        display_ = { time_zone: 'system', date_format: 'system', time_format: 'system', theme: 'light' };
        upstreamText = '';
        rootHintsText = '';
        rateLimit_ = {};
        dotNetworks = [];
        dohNetworks = [];
        doqNetworks = [];
        return;
      }
      server = { ...config.server };
      recursive = { ...config.recursive };
      // An unset mode means: forwarding when upstreams exist, else recursive.
      recursive.mode = config.recursive.mode || (config.recursive.upstreams?.length ? 'forwarding' : 'recursive');
      recursive.outbound_ip_versions = config.recursive.outbound_ip_versions || 'both';
      dot = { ...config.dot };
      doh = { ...config.doh };
      doq = { ...config.doq };
      dotNetworks = [...(config.dot?.allowed_networks || [])];
      dohNetworks = [...(config.doh?.allowed_networks || [])];
      doqNetworks = [...(config.doq?.allowed_networks || [])];
      api_ = { ...config.api };
      display_ = { time_zone: 'system', date_format: 'system', time_format: 'system', theme: 'light', ...config.display };
      web_ = {
        http_enabled: true, https_enabled: false, https_port: 5443, https_certificate: '', redirect_http: false,
        ...config.web,
        http_port: config.web?.http_port || config.api?.port || 5380,
      };
      syslog_ = { enabled: false, server: '', facility: 'daemon', level: 'info', queries: false, ...config.syslog };
      export_ = { ...EXPORT_DEFAULTS, ...config.log_export };
      dnstap_ = { ...DNSTAP_DEFAULTS, ...config.dnstap };
      logging_ = Object.fromEntries(
        Object.entries(LOGGING_DEFAULTS).map(([k, v]) => [k, config.logging?.[k] ?? v]),
      );
      alerts_ = { ...ALERT_DEFAULTS, ...config.alerts };
      rrl_ = { ...RRL_DEFAULTS, ...config.rrl };
      rateLimit_ = { ...config.rate_limit };
      ddr_ = { enabled: true, name: '', ...config.ddr };
      reports_ = { ...REPORT_DEFAULTS, ...config.reports };
      rrlExempt = [...(config.rrl?.exempt || [])];
      alertTo = (config.alerts?.email_to || []).join('\n');
      dns64 = { enabled: !!config.dns64?.enabled, prefix: config.dns64?.prefix || '64:ff9b::/96' };
      dns64Clients = [...(config.dns64?.clients || [])];
      ecs = { enabled: false, subnet: '', ipv4_prefix: 24, ipv6_prefix: 56, ...config.ecs };
      dotCertMode = certModeOf(dot);
      dohCertMode = certModeOf(doh);
      doqCertMode = certModeOf(doq);
      upstreamText = (recursive.upstreams || []).join('\n');
      rootHintsText = (recursive.root_hints || []).join('\n');
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

  // What each tab's Reset to Defaults leaves alone: things typed for this
  // network (addresses, lists, names, credentials, certificates) rather
  // than tuning. The General tab's web access is left too, so a reset can
  // never move the console out from under the browser.
  const RESET_KEEPS = {
    general: 'Web console access is kept.',
    recursive: 'Upstream servers, DNS64 clients and the ECS subnet are kept.',
    listeners: 'Certificates, server names, allowed networks and the DDR name are kept. Listen addresses are set in the config file.',
    logging: 'The syslog server is kept.',
    'rate-limiting': 'The never-limited list is kept.',
    alerts: 'The webhook, email server, sender and recipients are kept.',
  };

  // Fill the current tab's fields with the built-in defaults. Nothing is
  // saved until Save Changes, so Discard Changes undoes it.
  async function resetTab() {
    const label = TABS.find(([id]) => id === tab)?.[1] || tab;
    const keeps = RESET_KEEPS[tab] ? ` ${RESET_KEEPS[tab]}` : '';
    if (!confirm(`Reset the ${label} settings to their defaults?${keeps} Nothing is saved until you click Save Changes.`)) return;
    notice = null;
    error = null;
    let d;
    try {
      d = await api.configDefaults();
    } catch (e) {
      error = formatApiError(e);
      return;
    }
    const pick = (src, keys) => Object.fromEntries(keys.map((k) => [k, src[k]]));
    const r = d.recursive;
    if (tab === 'general') {
      display_ = { time_zone: 'system', date_format: 'system', time_format: 'system', ...d.display };
    } else if (tab === 'recursive') {
      rootHintsText = (r.root_hints || []).join('\n');
      recursive = {
        ...recursive,
        ...pick(r, ['enabled', 'dnssec_validate', 'dnssec_reject_bogus', 'case_randomization', 'rebinding_protection',
          'opportunistic_encryption', 'use_system_config', 'timeout_secs', 'max_concurrent_lookups']),
        // An unset mode means: forwarding when upstreams exist, else recursive.
        mode: r.mode || (parseUpstreams(upstreamText).length ? 'forwarding' : 'recursive'),
        outbound_ip_versions: r.outbound_ip_versions || 'both',
      };
      server = { ...server, client_timeout_ms: d.server.client_timeout_ms };
      dns64 = { ...dns64, enabled: !!d.dns64?.enabled, prefix: d.dns64?.prefix || '64:ff9b::/96' };
      ecs = { ...ecs, ...pick(d.ecs, ['enabled', 'ipv4_prefix', 'ipv6_prefix']) };
    } else if (tab === 'listeners') {
      server = { ...server, ...pick(d.server, ['tcp_timeout_ms', 'tcp_max_connections', 'dns_cookies']) };
      ddr_ = { ...ddr_, enabled: d.ddr.enabled };
      dot = { ...dot, ...pick(d.dot, ['enabled', 'port', 'handshake_timeout_secs', 'idle_timeout_secs', 'max_connections']) };
      doh = { ...doh, ...pick(d.doh, ['enabled', 'port', 'handshake_timeout_secs', 'max_connections', 'endpoint', 'http3']) };
      doq = { ...doq, ...pick(d.doq, ['enabled', 'port', 'max_connections', 'max_concurrent_streams', 'idle_timeout_secs']) };
    } else if (tab === 'logging') {
      syslog_ = { ...syslog_, ...pick(d.syslog, ['enabled', 'facility', 'level', 'queries']) };
      logging_ = { ...logging_, ...pick(d.logging, Object.keys(LOGGING_DEFAULTS)) };
    } else if (tab === 'rate-limiting') {
      // The never-limited list lives in rrlExempt, which is left alone.
      rrl_ = { ...rrl_, ...d.rrl };
      rateLimit_ = { ...d.rate_limit };
    } else if (tab === 'alerts') {
      alerts_ = {
        ...alerts_,
        enabled: d.alerts.enabled,
        smtp_port: d.alerts.smtp_port,
        smtp_security: d.alerts.smtp_security,
        ...pick(d.alerts, ALERT_EVENTS.map(([key]) => key)),
      };
      reports_ = { ...reports_, ...d.reports };
    }
    notice = `${label} settings reset to their defaults. Click Save Changes to apply them.`;
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

  // Everything the page edits, in the shape PUT /api/config takes. The
  // DNS Listeners tab's addresses and the console switch are config-file owned
  // (a broken listener can always be fixed by editing the file), so they
  // are shown but not sent.
  function buildBody() {
    return {
      recursive: {
        enabled: !!recursive.enabled,
        mode: recursive.mode,
        case_randomization: !!recursive.case_randomization,
        rebinding_protection: !!recursive.rebinding_protection,
        opportunistic_encryption: !!recursive.opportunistic_encryption,
        outbound_ip_versions: recursive.outbound_ip_versions,
        upstreams: parseUpstreams(upstreamText),
        use_system_config: !!recursive.use_system_config,
        dnssec_validate: !!recursive.dnssec_validate,
        dnssec_reject_bogus: !!recursive.dnssec_reject_bogus,
        max_concurrent_lookups: Number(recursive.max_concurrent_lookups),
        timeout_secs: Number(recursive.timeout_secs),
        root_hints: parseUpstreams(rootHintsText),
      },
      server: {
        client_timeout_ms: Number(server.client_timeout_ms),
        tcp_timeout_ms: Number(server.tcp_timeout_ms),
        tcp_max_connections: Number(server.tcp_max_connections),
        dns_cookies: !!server.dns_cookies,
      },
      rate_limit: {
        enabled: !!rateLimit_.enabled,
        client_max_queries: Number(rateLimit_.client_max_queries),
        client_window_secs: Number(rateLimit_.client_window_secs),
        domain_max_queries: Number(rateLimit_.domain_max_queries),
        domain_window_secs: Number(rateLimit_.domain_window_secs),
        exempt_loopback: !!rateLimit_.exempt_loopback,
        client_ipv6_prefix: Number(rateLimit_.client_ipv6_prefix),
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
        idle_timeout_secs: Number(dot.idle_timeout_secs),
        max_connections: Number(dot.max_connections),
        allowed_networks: [...dotNetworks],
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
        max_connections: Number(doh.max_connections),
        allowed_networks: [...dohNetworks],
        http3: !!doh.http3,
      },
      doq: {
        enabled: !!doq.enabled,
        port: Number(doq.port),
        self_signed: !!doq.self_signed,
        server_name: doq.server_name,
        cert_path: doq.cert_path || '',
        key_path: doq.key_path || '',
        certificate: doq.certificate || '',
        max_connections: Number(doq.max_connections),
        max_concurrent_streams: Number(doq.max_concurrent_streams),
        idle_timeout_secs: Number(doq.idle_timeout_secs),
        allowed_networks: [...doqNetworks],
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
        clients: [...dns64Clients],
      },
      ecs: {
        enabled: !!ecs.enabled,
        subnet: (ecs.subnet || '').trim(),
        ipv4_prefix: Number(ecs.ipv4_prefix),
        ipv6_prefix: Number(ecs.ipv6_prefix),
      },
      alerts: alertsBody(),
      ddr: { enabled: !!ddr_.enabled, name: (ddr_.name || '').trim() },
      reports: reportsBody(),
      rrl: {
        enabled: !!rrl_.enabled,
        responses_per_second: Number(rrl_.responses_per_second),
        nxdomains_per_second: Number(rrl_.nxdomains_per_second),
        errors_per_second: Number(rrl_.errors_per_second),
        window_secs: Number(rrl_.window_secs),
        slip: Number(rrl_.slip),
        ipv4_prefix: Number(rrl_.ipv4_prefix),
        ipv6_prefix: Number(rrl_.ipv6_prefix),
        exempt: [...rrlExempt],
        log_only: !!rrl_.log_only,
      },
      syslog: {
        enabled: !!syslog_.enabled,
        server: (syslog_.server || '').trim(),
        facility: syslog_.facility || 'daemon',
        level: syslog_.level || 'info',
        queries: !!syslog_.queries,
      },
      log_export: exportBody(),
      dnstap: dnstapBody(),
      logging: {
        query_db_enabled: !!logging_.query_db_enabled,
        query_db_max_rows: Number(logging_.query_db_max_rows) || 0,
        query_db_retention_days: Number(logging_.query_db_retention_days) || 0,
        query_log_enabled: !!logging_.query_log_enabled,
        query_log_dir: (logging_.query_log_dir || '').trim(),
        query_log_retention_days: Number(logging_.query_log_retention_days) || 0,
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
        notice = `Settings saved. The console has moved: opening ${next} ...`;
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
    <button onclick={save} disabled={busy || !dirty}>{busy ? 'Saving...' : 'Save Changes'}</button>
    <button class="secondary" onclick={reload} disabled={busy}>{dirty ? 'Discard Changes' : 'Reload'}</button>
    <button class="secondary" onclick={resetTab} disabled={busy}>Reset to Defaults</button>
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
    <h3 style="margin: 0 0 10px">Display Defaults</h3>
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
      <label><span>Theme</span>
        <select bind:value={display_.theme}>
          {#each THEME_OPTIONS as [value, label]}<option value={value}>{label}</option>{/each}
        </select>
      </label>
    </div>
    <p class="muted help">
      Example: <strong>{previewDateTime(display_)}</strong>. These are the
      defaults for every user. Each user can choose their own under
      the Preferences tab of their <strong>Account</strong> page.
      {#if ownPrefsSet}Your own preferences are set, so you won't see a change
        here until you reset them.{/if}
      "Device Time Zone", "Browser Default" and "Match the Device" follow each
      viewer's computer.
      Filtering group schedules also use this time zone ("Device Time Zone"
      there means the server's own).
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
      <label class="check"><input type="checkbox" bind:checked={recursive.dnssec_reject_bogus} disabled={!recursive.enabled || !recursive.dnssec_validate} /> <span>Reject Answers That Fail Validation</span></label>
      <label class="check"><input type="checkbox" bind:checked={recursive.rebinding_protection} disabled={!recursive.enabled} /> <span>DNS Rebinding Protection</span></label>
    </div>
    {#if recursive.enabled}
      <p class="muted help">
        With DNSSEC validation, rejecting refuses an answer that fails it
        (SERVFAIL) rather than passing it on unchecked. A name the validator
        wrongly fails then stops resolving, so it is off unless you turn it
        on.
      </p>
      <p class="muted help">
        Rebinding protection blocks answers that give a public name a private,
        loopback or link-local address, for every client and in both modes (a
        filtering group can turn it on for its own clients only). Local names
        (single labels, .lan, .home.arpa, .local, .internal and the like),
        conditional forwarders, stub zones, your own zones and the allowlist
        are not affected.
      </p>
    {/if}
    {#if !recursive.enabled}
      <p class="help restart">
        Recursion is off: the server answers only for its own zones and
        refuses everything else.
      </p>
    {:else if recursive.mode === 'recursive'}
      <div class="form-grid" style="margin-top: 4px">
        <label class="check"><input type="checkbox" bind:checked={recursive.case_randomization} /> <span>Randomize Query Case (0x20)</span></label>
        <label class="check"><input type="checkbox" bind:checked={recursive.opportunistic_encryption} /> <span>Opportunistic Encryption</span></label>
      </div>
      <p class="muted help">
        Daygle DNS resolves names itself, starting at the root servers, so no upstream
        provider sees your queries. Query names are minimized (RFC 9156) and DNSSEC
        is validated against the root trust anchor. Query-case randomization makes
        spoofed answers harder to inject but can fail with the odd server that does
        not preserve case. Opportunistic encryption (RFC 9539) probes nameservers for DNS
        over TLS or QUIC in the background and uses it where it works, falling back
        to plain DNS; it is experimental and adds some connection overhead.
      </p>
      <label class="stacked" style="margin-top: 12px">
        <span>Root Hints (one address per line; empty uses the built-in root servers)</span>
        <textarea rows="3" bind:value={rootHintsText} placeholder={'198.41.0.4\n2001:503:ba3e::2:30'}></textarea>
      </label>
      <p class="muted help">
        The servers resolution starts from. Leave empty to use the 13 IANA root
        servers built in; the full current list is fetched from whichever of
        these answers first.
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
      <h4>Timeouts and Limits</h4>
      <div class="form-grid">
        <label><span>Per-Server Timeout (Seconds)</span><input type="number" min="1" max="300" bind:value={recursive.timeout_secs} /></label>
        <label><span>Client Timeout (Milliseconds)</span><input type="number" min="1000" max="10000" step="100" bind:value={server.client_timeout_ms} /></label>
        <label><span>Maximum Concurrent Lookups</span><input type="number" min="1" max="65536" bind:value={recursive.max_concurrent_lookups} /></label>
      </div>
      <p class="muted help">
        Per-Server Timeout is how long to wait for one
        {recursive.mode === 'recursive' ? 'name server' : 'upstream server'}
        before trying the next. Client Timeout is how long a client waits for
        a lookup (1000-10000 ms): when it runs out the client gets the expired
        answer if there is one (Serve-Stale, Cache → Settings), else SERVFAIL,
        and the lookup carries on to fill the cache. Raise it if slow sites
        fail on first visit. Maximum Concurrent Lookups caps the outbound
        lookups in flight at once.
      </p>
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
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS64 (RFC 6147)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={dns64.enabled} /> <span>Make IPv6 Answers for IPv4-Only Names</span></label>
      <label><span>NAT64 Prefix</span><input placeholder="64:ff9b::/96" bind:value={dns64.prefix} disabled={!dns64.enabled} spellcheck="false" /></label>
    </div>
    <div class="stacked" style="margin-top: 12px" inert={!dns64.enabled}>
      <span>Clients (empty means every client)</span>
      <NetworkPicker {networks} bind:value={dns64Clients} />
    </div>
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
      servers. An answer for one client's own network is never given to
      another: those lookups skip this server's cache and go to the upstream
      each time (it keeps its own per-network cache), while clients on private
      addresses, and a fixed network, are cached as usual.
    </p>
  </div>
  {:else if tab === 'listeners'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Plain DNS (UDP and TCP)</h3>
    <table class="facts">
      <tbody>
        <tr><th>Listen Address</th><td>{listenMeaning(server.listen, server.ipv6_only)} <span class="muted">({server.listen})</span></td></tr>
        <tr><th>Port</th><td>{server.port}</td></tr>
        <tr><th>PROXY Protocol From</th><td>{(server.proxy_protocol || []).length ? server.proxy_protocol.join(', ') : 'Off'}</td></tr>
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
      listens on {config?.api?.listen}; its ports are on the General tab.
    </p>
    <div class="form-grid" style="margin-top: 12px">
      <label><span>TCP Idle Timeout (Milliseconds)</span><input type="number" min="100" max="3600000" step="100" bind:value={server.tcp_timeout_ms} /></label>
      <label><span>TCP Maximum Connections</span><input type="number" min="1" max="65536" bind:value={server.tcp_max_connections} /></label>
      <label class="check"><input type="checkbox" bind:checked={server.dns_cookies} /> <span>DNS Cookies (RFC 7873)</span></label>
    </div>
    <p class="muted help">
      TCP Idle Timeout is how long a plain DNS-over-TCP connection may sit
      unused before it is closed. TCP Maximum Connections caps the plain TCP
      connections served at once; one public client may hold an eighth of
      them (private and loopback clients are not capped individually), and
      the queries of one connection are answered concurrently. DNS cookies let clients prove they really
      own their address, which protects against spoofed queries; clients that
      send a valid cookie are never response-rate-limited and get ten times
      the per-client query limit (Rate Limiting tab). Changing any of these
      restarts the DNS listeners for a moment.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS over TLS</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={dot.enabled} /> <span>Enabled</span></label>
      <label><span>Port</span><input type="number" bind:value={dot.port} /></label>
      <label><span>Handshake Timeout (Seconds)</span><input type="number" min="1" max="600" bind:value={dot.handshake_timeout_secs} /></label>
      <label><span>Session Idle Timeout (Seconds)</span><input type="number" min="1" max="3600" bind:value={dot.idle_timeout_secs} /></label>
      <label><span>Maximum Connections</span><input type="number" min="1" max="65536" bind:value={dot.max_connections} /></label>
      <label>
        <span>Certificate</span>
        <select bind:value={dotCertMode} onchange={(e) => applyCertMode(dot, e.currentTarget.value)}>
          <option value="self">Self-Signed (Generated Automatically)</option>
          {#each certs as cert (cert.name)}
            <option value={cert.name}>{certLabel(cert)}</option>
          {/each}
          <option value="custom">Certificate Files on the Server...</option>
        </select>
      </label>
      {#if dotCertMode === 'self'}
        <label><span>Server Name</span><input bind:value={dot.server_name} placeholder="dns.example.com" /></label>
      {:else if dotCertMode === 'custom'}
        <label><span>Certificate Path</span><input bind:value={dot.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
        <label><span>Key Path</span><input bind:value={dot.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
      {/if}
    </div>
    <div class="stacked" style="margin-top: 12px">
      <span>Client Networks (empty means everyone)</span>
      <NetworkPicker {networks} bind:value={dotNetworks} />
    </div>
    <p class="muted help">
      Clients connect to port {dot.port || 853} (the standard port is 853).
      Clients outside these networks get REFUSED on this listener; clients
      inside it may use recursion here even when Recursion Access (Clients →
      Access) is set to Private Networks Only. An established session is
      closed after the idle timeout; responses tell clients that timeout in
      EDNS keepalive, so a longer value keeps devices from reconnecting (and
      handshaking again) after every quiet moment.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS over HTTPS</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={doh.enabled} /> <span>Enabled</span></label>
      <label><span>Port</span><input type="number" bind:value={doh.port} /></label>
      <label><span>Handshake Timeout (Seconds)</span><input type="number" min="1" max="600" bind:value={doh.handshake_timeout_secs} /></label>
      <label><span>Maximum Connections</span><input type="number" min="1" max="65536" bind:value={doh.max_connections} /></label>
      <label>
        <span>Certificate</span>
        <select bind:value={dohCertMode} onchange={(e) => applyCertMode(doh, e.currentTarget.value)}>
          <option value="self">Self-Signed (Generated Automatically)</option>
          {#each certs as cert (cert.name)}
            <option value={cert.name}>{certLabel(cert)}</option>
          {/each}
          <option value="custom">Certificate Files on the Server...</option>
        </select>
      </label>
      {#if dohCertMode === 'self'}
        <label><span>Server Name</span><input bind:value={doh.server_name} placeholder="dns.example.com" /></label>
      {:else if dohCertMode === 'custom'}
        <label><span>Certificate Path</span><input bind:value={doh.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
        <label><span>Key Path</span><input bind:value={doh.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
      {/if}
      <label><span>Endpoint Path</span><input bind:value={doh.endpoint} placeholder="/dns-query" /></label>
      <label class="check"><input type="checkbox" bind:checked={doh.http3} disabled={!doh.enabled} /> <span>Also Serve over HTTP/3 (QUIC)</span></label>
    </div>
    <div class="stacked" style="margin-top: 12px">
      <span>Client Networks (empty means everyone)</span>
      <NetworkPicker {networks} bind:value={dohNetworks} />
    </div>
    <p class="muted help">Clients use <code>https://{doh.server_name || 'this-server'}{Number(doh.port) === 443 ? '' : `:${doh.port}`}{doh.endpoint || '/dns-query'}</code>. The standard port is 443. Clients outside these networks get REFUSED on this listener; clients inside it may use recursion here even when Recursion Access is set to Private Networks Only.</p>
    <p class="muted help">
      HTTP/3 serves the same address over QUIC, on UDP port {doh.port || 443}
      (open it in your firewall as well as TCP), with the same certificate,
      path and client networks. Clients set up for HTTP/3 DoH (for example
      AdGuard's or dnsproxy's <code>h3://</code> addresses) and devices using
      Automatic Discovery below can use it; browsers keep using HTTP/2. It
      cannot share its UDP port with DNS over QUIC.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">DNS over QUIC</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={doq.enabled} /> <span>Enabled</span></label>
      <label><span>Port</span><input type="number" bind:value={doq.port} /></label>
      <label><span>Maximum Connections</span><input type="number" min="1" max="65536" bind:value={doq.max_connections} /></label>
      <label><span>Concurrent DNS Streams per Connection</span><input type="number" min="1" max="65536" bind:value={doq.max_concurrent_streams} /></label>
      <label><span>Idle Timeout (Seconds)</span><input type="number" min="30" bind:value={doq.idle_timeout_secs} /></label>
      <label>
        <span>Certificate</span>
        <select bind:value={doqCertMode} onchange={(e) => applyCertMode(doq, e.currentTarget.value)}>
          <option value="self">Self-Signed (Generated Automatically)</option>
          {#each certs as cert (cert.name)}
            <option value={cert.name}>{certLabel(cert)}</option>
          {/each}
          <option value="custom">Certificate Files on the Server...</option>
        </select>
      </label>
      {#if doqCertMode === 'self'}
        <label><span>Server Name</span><input bind:value={doq.server_name} placeholder="dns.example.com" /></label>
      {:else if doqCertMode === 'custom'}
        <label><span>Certificate Path</span><input bind:value={doq.cert_path} placeholder="/etc/daygle-dns/certs/server.crt" /></label>
        <label><span>Key Path</span><input bind:value={doq.key_path} placeholder="/etc/daygle-dns/certs/server.key" /></label>
      {/if}
    </div>
    <div class="stacked" style="margin-top: 12px">
      <span>Client Networks (empty means everyone)</span>
      <NetworkPicker {networks} bind:value={doqNetworks} />
    </div>
    <p class="muted help">
      Clients connect to UDP port {doq.port || 853} (the standard port is 853).
      An idle connection is closed after the idle timeout (RFC 9250
      recommends at least 600 seconds; the minimum is 30).
      Clients outside these networks get REFUSED on this listener; clients
      inside it may use recursion here even when Recursion Access (Clients →
      Access) is set to Private Networks Only.
      Manage certificates, and see when they expire, on the Certificates page.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Automatic Discovery (DDR)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={ddr_.enabled} /> <span>Advertise Encrypted DNS to Devices</span></label>
      <label><span>Server Name (Optional)</span><input bind:value={ddr_.name} placeholder="dns.example.com" disabled={!ddr_.enabled} spellcheck="false" /></label>
    </div>
    <p class="muted help">
      Devices that support Discovery of Designated Resolvers (RFC 9462) -
      Windows 11, iOS and macOS, Android - ask this server whether it also
      offers encrypted DNS, and switch to the DNS over HTTPS, TLS or QUIC
      listeners above by themselves; each device is only told about the
      listeners it is allowed on. Most devices only switch when the
      listener's certificate is one they trust and it covers the address
      they use for this server, so a self-signed certificate is usually
      ignored. Nothing is advertised while DNS accounts are required, since a
      device that switched by itself would carry no account and be refused.
      The server name is the name devices connect to; leave it empty to use
      each listener's own certificate name.
    </p>
  </div>
  {:else if tab === 'logging'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Query Log</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={logging_.query_db_enabled} /> <span>Keep a Searchable Query Log</span></label>
      <label>
        <span>Keep Queries For</span>
        <select bind:value={logging_.query_db_retention_days} disabled={!logging_.query_db_enabled}>
          {#each KEEP_DAYS.includes(Number(logging_.query_db_retention_days)) ? KEEP_DAYS : [...KEEP_DAYS, Number(logging_.query_db_retention_days)].sort((a, b) => a - b) as d (d)}
            <option value={d}>{d ? `${d} Days` : 'No Time Limit'}</option>
          {/each}
        </select>
      </label>
      <label>
        <span>At Most (Entries)</span>
        <input type="number" min="0" step="10000" bind:value={logging_.query_db_max_rows} disabled={!logging_.query_db_enabled} />
      </label>
    </div>
    <p class="muted help">
      Every answered query, for Logs → Query Log and the Reports page, which
      only see what is kept here. The oldest entries go once either limit is
      reached, whichever comes first; 0 entries means no limit on the number.
      Changes apply as soon as they are saved.
      {#if queryLogStats}
        <br />
        Now holding {queryLogStats.rows.toLocaleString()} queries{#if queryLogStats.oldest}, going back to {formatDateTime(queryLogStats.oldest)}{/if}.
        The database (settings, zones and logs together) is {fmtBytes(queryLogStats.database_bytes)}.
      {/if}
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Query Log Files</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={logging_.query_log_enabled} /> <span>Also Write Daily Log Files</span></label>
      <label>
        <span>Folder</span>
        <input placeholder="/var/log/daygle-dns" bind:value={logging_.query_log_dir} disabled={!logging_.query_log_enabled} spellcheck="false" />
      </label>
      <label>
        <span>Keep Files For (Days)</span>
        <input type="number" min="0" max="3650" bind:value={logging_.query_log_retention_days} disabled={!logging_.query_log_enabled} />
      </label>
    </div>
    <p class="muted help">
      One file per day (<code>queries-YYYY-MM-DD.log</code>, a JSON object per
      line) for other tools to read. Files older than the limit are deleted;
      0 keeps them all. The service needs write access to the folder.
      These settings take effect after the service restarts.
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
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Query Export (HTTP)</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={export_.enabled} /> <span>Send Every Query to a Log Collector</span></label>
      <label>
        <span>Endpoint URL</span>
        <input placeholder="https://logs.example.com:8088/ingest" bind:value={export_.url} disabled={!export_.enabled} spellcheck="false" />
      </label>
      <label>
        <span>Format</span>
        <select bind:value={export_.format} disabled={!export_.enabled}>
          <option value="ndjson">NDJSON (One Query per Line)</option>
          <option value="json">JSON Array</option>
        </select>
      </label>
      <label>
        <span>Authorization Header</span>
        <input type="password" autocomplete="new-password" placeholder="Bearer abc123" bind:value={export_.authorization} disabled={!export_.enabled} />
      </label>
      <label><span>Queries per Request</span><input type="number" min="1" max="10000" bind:value={export_.batch_size} disabled={!export_.enabled} /></label>
      <label><span>Send at Least Every (Seconds)</span><input type="number" min="1" max="300" bind:value={export_.flush_secs} disabled={!export_.enabled} /></label>
    </div>
    <div class="row" style="margin-top: 14px; gap: 10px; flex-wrap: wrap; align-items: center">
      <button class="secondary" onclick={testExport} disabled={exportTesting || !(export_.url || '').trim()}>{exportTesting ? 'Sending...' : 'Send Test Query'}</button>
      {#if exportTest}<span style="color: {exportTest.ok ? 'var(--ok)' : 'var(--danger)'}">{exportTest.msg}</span>{/if}
    </div>
    {#if exportStatus && (exportStatus.sent || exportStatus.dropped || exportStatus.last_error)}
      <p class="muted help">
        Since the server started: {exportStatus.sent.toLocaleString()} queries sent, {exportStatus.dropped.toLocaleString()} dropped.
        {#if exportStatus.last_error}<span style="color: var(--danger)">Last error: {exportStatus.last_error}</span>{/if}
      </p>
    {/if}
    <p class="muted help">
      Queries are sent in batches as an HTTP <code>POST</code>, each a JSON
      object with <code>time</code>, <code>server</code>, <code>client</code>,
      <code>qname</code>, <code>qtype</code>, <code>protocol</code>,
      <code>outcome</code>, <code>rcode</code> and <code>elapsed_ms</code>, for
      Vector, Fluent Bit, Logstash, Splunk HEC (<code>Splunk &lt;token&gt;</code>)
      and the like. The Authorization header, when set, is never shown again
      (leave it as is to keep it). A batch the endpoint does not accept is
      retried twice, then dropped; Send Test Query uses the settings on this
      page, saved or not.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">dnstap</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={dnstap_.enabled} /> <span>Stream Every Query and Response to a dnstap Collector</span></label>
      <label>
        <span>Collector</span>
        <input placeholder="tcp://127.0.0.1:6000" bind:value={dnstap_.server} spellcheck="false" />
      </label>
      <label>
        <span>Identity</span>
        <input placeholder="This host's name" bind:value={dnstap_.identity} spellcheck="false" />
      </label>
      <label>
        <span>Version</span>
        <input placeholder="This build's version" bind:value={dnstap_.version} spellcheck="false" />
      </label>
    </div>
    <div class="row" style="margin-top: 14px; gap: 10px; flex-wrap: wrap; align-items: center">
      <button class="secondary" onclick={testDnstap} disabled={dnstapTesting || !(dnstap_.server || '').trim()}>{dnstapTesting ? 'Connecting...' : 'Send Test Event'}</button>
      {#if dnstapTest}<span style="color: {dnstapTest.ok ? 'var(--ok)' : 'var(--danger)'}">{dnstapTest.msg}</span>{/if}
    </div>
    <p class="muted help">
      Every client query and the exact response sent back are streamed as
      dnstap events (<code>dnstap.Message</code> protobufs) over Frame Streams
      to a collector such as dnstap-ldns, fstrm_capture, dnstap-receiver or
      DNS-collector - <code>tcp://host:port</code>, a bare
      <code>host:port</code>, or <code>unix:/path/to/socket</code> on Unix.
      Events are queued in memory (8192) and dropped rather than ever delaying
      a query, so a collector that stops reading loses events, not answers.
      Send Test Event connects, completes the handshake and sends one sample
      query, using the settings on this page, saved or not, and reports why
      it failed.
    </p>
  </div>
  {:else if tab === 'rate-limiting'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Query Rate Limiting</h3>
    <label class="check"><input type="checkbox" bind:checked={rateLimit_.enabled} /> <span>Limit Queries per Client and per Domain</span></label>
    <div class="form-grid" style="margin-top: 10px">
      <label><span>Queries per Client</span><input type="number" min="1" bind:value={rateLimit_.client_max_queries} disabled={!rateLimit_.enabled} /></label>
      <label><span>Per Client Window (Seconds)</span><input type="number" min="1" bind:value={rateLimit_.client_window_secs} disabled={!rateLimit_.enabled} /></label>
      <label><span>Queries per Domain</span><input type="number" min="1" bind:value={rateLimit_.domain_max_queries} disabled={!rateLimit_.enabled} /></label>
      <label><span>Per Domain Window (Seconds)</span><input type="number" min="1" bind:value={rateLimit_.domain_window_secs} disabled={!rateLimit_.enabled} /></label>
      <label><span>IPv6 Client Network Size (Prefix)</span><input type="number" min="1" max="128" bind:value={rateLimit_.client_ipv6_prefix} disabled={!rateLimit_.enabled} /></label>
      <label class="check"><input type="checkbox" bind:checked={rateLimit_.exempt_loopback} disabled={!rateLimit_.enabled} /> <span>Never Limit This Server (Loopback)</span></label>
    </div>
    <p class="muted help">
      Caps how many queries one client, and one domain name, may send in each
      window; queries over the limit get SERVFAIL and are counted as Rate
      Limited on the Dashboard and in the query log. This protects the server
      from a misbehaving device or a flood of lookups for one name. IPv6
      clients are counted per network of the given size, since one device
      usually holds a whole /64. Changes apply immediately.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Response Rate Limiting (RRL)</h3>
    <label class="check"><input type="checkbox" bind:checked={rrl_.enabled} /> <span>Limit Identical Responses</span></label>
    <p class="muted help">
      An attacker can send queries with a victim's address as the sender, so
      this server's answers (often far larger than the queries) flood the
      victim. RRL limits how many identical answers each network gets per
      second over UDP. Over the limit, answers are dropped, except that some
      are sent truncated: a real client then asks again over TCP and gets its
      answer, while a forged one cannot. TCP, and clients with a valid DNS
      cookie, are never limited. Most useful when this server answers the
      internet (authoritative zones, public DNS); on a private network it can
      stay off.
    </p>
    <div class="form-grid" style="margin-top: 12px">
      <label><span>Identical Answers per Second</span><input type="number" min="0" max="10000" bind:value={rrl_.responses_per_second} disabled={!rrl_.enabled} /></label>
      <label><span>NXDOMAIN Answers per Second</span><input type="number" min="0" max="10000" bind:value={rrl_.nxdomains_per_second} disabled={!rrl_.enabled} /></label>
      <label><span>Error Answers per Second</span><input type="number" min="0" max="10000" bind:value={rrl_.errors_per_second} disabled={!rrl_.enabled} /></label>
      <label><span>Window (Seconds)</span><input type="number" min="1" max="3600" bind:value={rrl_.window_secs} disabled={!rrl_.enabled} /></label>
      <label>
        <span>Slip</span>
        <select bind:value={rrl_.slip} disabled={!rrl_.enabled}>
          <option value={0}>Drop All Limited Answers</option>
          <option value={1}>Truncate All Limited Answers</option>
          {#each [2, 3, 4, 5, 6, 7, 8, 9, 10] as n (n)}<option value={n}>Truncate 1 in {n}</option>{/each}
        </select>
      </label>
      <label><span>IPv4 Network Size (Prefix)</span><input type="number" min="8" max="32" bind:value={rrl_.ipv4_prefix} disabled={!rrl_.enabled} /></label>
      <label><span>IPv6 Network Size (Prefix)</span><input type="number" min="16" max="128" bind:value={rrl_.ipv6_prefix} disabled={!rrl_.enabled} /></label>
    </div>
    <label class="check" style="margin-top: 10px"><input type="checkbox" bind:checked={rrl_.log_only} disabled={!rrl_.enabled} /> <span>Log Only (Count, Do Not Limit)</span></label>
    <p class="muted help">
      Answers count as identical when they are for the same name and type;
      NXDOMAIN answers count per parent domain (so a flood of random names
      under one domain shares a limit), and errors count per network. 0 means
      no limit for that kind. The window is how long a network that went over
      the limit stays limited after it slows down. Clients are grouped into
      networks of the given size (/24 and /56 by default, as in BIND). Log
      Only counts what would be limited without limiting anything, to check
      the rates first.
    </p>
    {#if rrlCounts}
      <p class="muted help">
        Since the server started: <strong>{Number(rrlCounts.rrl_dropped || 0).toLocaleString()}</strong> dropped,
        <strong>{Number(rrlCounts.rrl_slipped || 0).toLocaleString()}</strong> sent truncated,
        <strong>{Number(rrlCounts.rrl_would_limit || 0).toLocaleString()}</strong> would have been limited (Log Only).
      </p>
    {/if}
    <h4>Never Limited</h4>
    <NetworkPicker {networks} bind:value={rrlExempt} />
    <p class="muted help">
      Networks whose answers are never response-rate-limited, such as your
      own networks and monitoring systems.
    </p>
  </div>
  {:else if tab === 'alerts'}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Webhook</h3>
    <div class="form-grid">
      <label>
        <span>Webhook URL</span>
        <input placeholder="https://hooks.slack.com/services/..." bind:value={alerts_.webhook_url} spellcheck="false" />
      </label>
    </div>
    <p class="muted help">
      Each alert is sent as a JSON <code>POST</code> with <code>kind</code>,
      <code>title</code>, <code>message</code>, <code>host</code> and
      <code>time</code>, plus <code>text</code> and <code>content</code> so
      Slack, Mattermost, Discord and Teams workflow webhooks show it as is.
      Alerts and the scheduled report below both use this webhook and the
      email settings. Leave empty for no webhook.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Email</h3>
    <div class="form-grid">
      <label><span>SMTP Server</span><input placeholder="smtp.example.com" bind:value={alerts_.smtp_server} spellcheck="false" /></label>
      <label><span>Port</span><input type="number" min="1" max="65535" bind:value={alerts_.smtp_port} /></label>
      <label>
        <span>Security</span>
        <select bind:value={alerts_.smtp_security}>
          <option value="starttls">STARTTLS (Usually Port 587)</option>
          <option value="tls">TLS (Usually Port 465)</option>
          <option value="none">None (Unencrypted)</option>
        </select>
      </label>
      <label><span>Username</span><input autocomplete="off" bind:value={alerts_.smtp_username} spellcheck="false" /></label>
      <label><span>Password</span><input type="password" autocomplete="new-password" bind:value={alerts_.smtp_password} /></label>
      <label><span>From</span><input placeholder="dns@example.com" bind:value={alerts_.email_from} spellcheck="false" /></label>
      <label><span>To</span><textarea rows="2" placeholder={'admin@example.com\nnoc@example.com'} bind:value={alertTo} spellcheck="false"></textarea></label>
    </div>
    <p class="muted help">
      Leave the server empty for no email. Username and password are only
      needed if the server asks for them; the saved password is never shown
      again (leave it as is to keep it). Recipients go one per line.
    </p>
    <div class="row" style="margin-top: 12px; gap: 10px; flex-wrap: wrap; align-items: center">
      <button class="secondary" onclick={testAlert} disabled={alertTesting}>{alertTesting ? 'Sending...' : 'Send Test Alert'}</button>
      {#if alertTest}<span style="color: {alertTest.ok ? 'var(--ok)' : 'var(--danger)'}">{alertTest.msg}</span>{/if}
    </div>
    <p class="muted help">
      Send Test Alert uses the settings on this page, saved or not, so you
      can check them before saving.
    </p>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Alerts</h3>
    <label class="check"><input type="checkbox" bind:checked={alerts_.enabled} /> <span>Send Alerts</span></label>
    <p class="muted help">
      Alerts go to the webhook, the email recipients, or both. A problem
      that persists is reported again after 6 hours at most (a day for certificates), not on
      every check, and an update is reported once per release.
    </p>
    <h4>Alert On</h4>
    <div class="events">
      {#each ALERT_EVENTS as [key, label] (key)}
        <label class="check"><input type="checkbox" bind:checked={alerts_[key]} /> <span>{label}</span></label>
      {/each}
    </div>
  </div>
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Scheduled Report</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={reports_.enabled} /> <span>Send a Report</span></label>
      <label>
        <span>How Often</span>
        <select bind:value={reports_.frequency}>
          <option value="daily">Daily (Last 24 Hours)</option>
          <option value="weekly">Weekly (Last 7 Days)</option>
        </select>
      </label>
      {#if reports_.frequency === 'weekly'}
        <label>
          <span>On</span>
          <select bind:value={reports_.weekday}>
            {#each [['mon', 'Monday'], ['tue', 'Tuesday'], ['wed', 'Wednesday'], ['thu', 'Thursday'], ['fri', 'Friday'], ['sat', 'Saturday'], ['sun', 'Sunday']] as [value, label] (value)}
              <option value={value}>{label}</option>
            {/each}
          </select>
        </label>
      {/if}
      <label>
        <span>At</span>
        <select bind:value={reports_.hour}>
          {#each Array.from({ length: 24 }, (_, h) => h) as h (h)}
            <option value={h}>{String(h).padStart(2, '0')}:00</option>
          {/each}
        </select>
      </label>
      <label><span>Entries per List</span><input type="number" min="1" max="50" bind:value={reports_.top} /></label>
    </div>
    <div class="row" style="margin-top: 14px; gap: 10px; flex-wrap: wrap; align-items: center">
      <button class="secondary" onclick={sendReportNow} disabled={reportSending}>{reportSending ? 'Sending...' : 'Send Report Now'}</button>
      {#if reportResult}<span style="color: {reportResult.ok ? 'var(--ok)' : 'var(--danger)'}">{reportResult.msg}</span>{/if}
    </div>
    <p class="muted help">
      A summary of the query log - queries, blocks, the most asked and most
      blocked domains and the most active devices - sent to the webhook and
      email above (alerts do not need to be switched on). Times use the time
      zone under General → Display Defaults. Send Report Now sends
      one with the destinations as saved. The same figures, for any period
      and per device, are on the Reports page.
    </p>
  </div>
  {:else if tab === 'backup'}
  <BackupRestore />
  {/if}
{:else}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{/if}

<style>
  .actions { display: flex; gap: 10px; margin-bottom: 16px; }
  .events { display: flex; flex-direction: column; gap: 8px; }
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
  .help.restart { color: var(--warn); margin-top: 8px; }
  /* Save bar: stays in view while scrolling a long tab. */
  .actions {
    position: sticky;
    top: 0;
    z-index: 5;
    align-items: center;
    padding: 10px 0;
    background: var(--bg);
  }
  .unsaved { color: var(--warn); font-size: 0.85rem; }
  .access { display: flex; flex-direction: column; gap: 10px; }
  .access-row { display: grid; grid-template-columns: 110px 140px minmax(0, 1fr); gap: 12px; align-items: end; }
  .access-row label.check { padding-bottom: 8px; }
  @media (max-width: 640px) {
    .access-row { grid-template-columns: 1fr 1fr; }
  }
  /* Below the field, so it never collides with a label that wraps. */
  .facts { width: auto; }
  .facts th { text-align: left; padding-right: 24px; color: var(--muted); font-weight: 500; }
</style>

<script>
  import { api } from '../api.js';

  let config = $state(null);
  let notice = $state(null);
  let error = $state(null);
  let busy = $state(false);

  // Local editable copies (bound to the form inputs).
  let server = $state({});
  let recursive = $state({});
  let dot = $state({});
  let doh = $state({});
  let doq = $state({});
  let api_ = $state({});
  let upstreamText = $state('');

  $effect(() => {
    load();
  });

  async function load() {
    error = null;
    try {
      config = await api.config();
      if (config == null) {
        server = {};
        recursive = {};
        dot = {};
        doh = {};
        doq = {};
        api_ = {};
        upstreamText = '';
        return;
      }
      server = { ...config.server };
      recursive = { ...config.recursive };
      dot = { ...config.dot };
      doh = { ...config.doh };
      doq = { ...config.doq };
      api_ = { ...config.api };
      upstreamText = (recursive.upstreams || []).join('\n');
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function parseUpstreams(text) {
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
        },
        dot: {
          enabled: !!dot.enabled,
          port: Number(dot.port),
          self_signed: !!dot.self_signed,
          server_name: dot.server_name,
        },
        doh: {
          enabled: !!doh.enabled,
          port: Number(doh.port),
          self_signed: !!doh.self_signed,
          server_name: doh.server_name,
          endpoint: doh.endpoint,
        },
        doq: {
          enabled: !!doq.enabled,
          port: Number(doq.port),
          self_signed: !!doq.self_signed,
          server_name: doq.server_name,
        },
        api: {
          gui_enabled: !!api_.gui_enabled,
          cors_origins: api_.cors_origins || [],
        },
      };
      await api.updateSettings(body);
      notice = 'Settings saved: applied live and persisted to the config file.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }
</script>

<h1>Settings</h1>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if config}
  <div class="actions">
    <button onclick={save} disabled={busy}>{busy ? 'Saving…' : 'Save settings'}</button>
    <button class="secondary" onclick={load} disabled={busy}>Reload from server</button>
    <button class="secondary" onclick={clearCache}>Flush recursive cache</button>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">DNS listeners</h3>
    <div class="form-grid">
      <label><span>Listen address</span><input bind:value={server.listen} /></label>
      <label><span>UDP/TCP port</span><input type="number" bind:value={server.port} /></label>
      <label class="check"><input type="checkbox" bind:checked={server.udp_enabled} /> <span>UDP enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={server.tcp_enabled} /> <span>TCP enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={server.reload_enabled} /> <span>Live config reload</span></label>
    </div>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Recursive resolver</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={recursive.enabled} /> <span>Recursion enabled</span></label>
      <label class="check"><input type="checkbox" bind:checked={recursive.dnssec_validate} /> <span>DNSSEC validation</span></label>
      <label><span>Upstream servers (one per line; supports <code>tls://</code> and <code>https://</code>)</span>
        <textarea rows="4" bind:value={upstreamText}></textarea>
      </label>
    </div>
    <h4>Caching</h4>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={recursive.prefetch_enabled} /> <span>Prefetch popular names</span></label>
      <label><span>Prefetch trigger (TTL fraction %)</span><input type="number" bind:value={recursive.prefetch_ttl_fraction_pct} /></label>
      <label><span>Prefetch minimum queries</span><input type="number" bind:value={recursive.prefetch_min_queries} /></label>
      <label><span>Serve-stale window (seconds)</span><input type="number" bind:value={recursive.serve_stale_secs} /></label>
    </div>
  </div>

  <div class="row" style="margin-bottom: 14px; align-items: stretch">
    <div class="card" style="flex: 1">
      <h3 style="margin-top: 0">DNS over TLS</h3>
      <div class="form-grid">
        <label class="check"><input type="checkbox" bind:checked={dot.enabled} /> <span>Enabled</span></label>
        <label><span>Port</span><input type="number" bind:value={dot.port} /></label>
        <label class="check"><input type="checkbox" bind:checked={dot.self_signed} /> <span>Self-signed certificate</span></label>
        <label><span>Certificate name</span><input bind:value={dot.server_name} /></label>
      </div>
    </div>
    <div class="card" style="flex: 1">
      <h3 style="margin-top: 0">DNS over HTTPS</h3>
      <div class="form-grid">
        <label class="check"><input type="checkbox" bind:checked={doh.enabled} /> <span>Enabled</span></label>
        <label><span>Port</span><input type="number" bind:value={doh.port} /></label>
        <label class="check"><input type="checkbox" bind:checked={doh.self_signed} /> <span>Self-signed certificate</span></label>
        <label><span>Certificate name</span><input bind:value={doh.server_name} /></label>
        <label><span>Endpoint path</span><input bind:value={doh.endpoint} /></label>
      </div>
    </div>
    <div class="card" style="flex: 1">
      <h3 style="margin-top: 0">DNS over QUIC</h3>
      <div class="form-grid">
        <label class="check"><input type="checkbox" bind:checked={doq.enabled} /> <span>Enabled</span></label>
        <label><span>Port</span><input type="number" bind:value={doq.port} /></label>
        <label class="check"><input type="checkbox" bind:checked={doq.self_signed} /> <span>Self-signed certificate</span></label>
        <label><span>Certificate name</span><input bind:value={doq.server_name} /></label>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Console</h3>
    <div class="form-grid">
      <label class="check"><input type="checkbox" bind:checked={api_.gui_enabled} /> <span>Serve the web GUI</span></label>
    </div>
    <p class="muted" style="font-size: 0.85rem">
      Login accounts, the API token, zone signing and remote blocklist sources
      are edited in <code>daygle-dns.toml</code>. Manage trusted and blocked
      domains from the Domain Lists page. Other advanced options likewise.
      Changes here are validated first - an invalid value is rejected and
      nothing is applied.
    </p>
  </div>
{:else}
  <p class="muted">Loading…</p>
{/if}

<style>
  .actions { display: flex; gap: 10px; margin-bottom: 16px; }
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

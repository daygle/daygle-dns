<script>
  import { api } from '../api.js';

  let sources = $state([]);
  let total = $state(0);
  let configured = $state(false); // false when the server has no sources configured
  let loading = $state(true);
  let refreshing = $state(false);
  let error = $state(null);
  let notice = $state(null);

  async function load() {
    loading = true;
    error = null;
    try {
      const data = await api.blocklistSources();
      sources = data.sources || [];
      total = data.total_domains || 0;
      // The endpoint returns 404 when no [[policy.blocklist_sources]] exist;
      // some servers answer 200 with an empty list instead - both mean
      // "nothing configured", never "still loading".
      configured = sources.length > 0;
    } catch (e) {
      sources = [];
      total = 0;
      configured = false;
      error = e.status === 404 ? null : String(e.message || e);
    } finally {
      loading = false;
    }
  }

  async function refreshNow() {
    refreshing = true;
    notice = null;
    try {
      const data = await api.refreshBlocklistSources();
      notice = `Refreshed - ${data.total_domains ?? 0} domains from remote sources.`;
      await load();
    } catch (e) {
      error = String(e.message || e);
    } finally {
      refreshing = false;
    }
  }

  $effect(() => {
    load();
  });

  function ago(secs) {
    if (secs === null || secs === undefined) return 'never';
    if (secs < 60) return 'just now';
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }
</script>

<h1>Blocklists</h1>

<div class="row" style="margin-bottom: 14px">
  <button class="secondary" onclick={load}>Refresh</button>
  <button onclick={refreshNow} disabled={refreshing || !configured}>
    {refreshing ? 'Refreshing…' : 'Refresh Now'}
  </button>
  {#if configured}
    <span class="muted">
      {sources.length} source{sources.length === 1 ? '' : 's'} · {fmt(total)} domains blocked
    </span>
  {/if}
</div>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if loading}
  <div class="card">
    <p class="muted">Loading…</p>
  </div>
{:else if !configured}
  <div class="card">
    <h3 style="margin-top: 0">No remote blocklist sources configured</h3>
    <p class="muted">
      Add sources to <code>daygle-dns.toml</code> and reload (or restart) the server.
      They are fetched over HTTP(S) and refreshed automatically.
    </p>
    <pre><code>[[policy.blocklist_sources]]
name = "StevenBlack hosts"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
format = "hosts"     # domains | hosts | adblock
refresh_secs = 86400</code></pre>
  </div>
{:else}
  <div class="card" style="padding: 0; overflow: auto">
    <table>
      <thead>
        <tr>
          <th>Source</th>
          <th>Format</th>
          <th>Refresh</th>
          <th style="text-align: right">Domains</th>
          <th>Last refresh</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {#each sources as s (s.url)}
          <tr class:disabled={!s.enabled}>
            <td>
              <strong>{s.name}</strong>
              <div class="muted" style="font-size: 0.78rem; max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">
                {s.url}
              </div>
            </td>
            <td><span class="pill">{s.format}</span></td>
            <td class="muted">{fmt(s.refresh_secs / 3600)} h</td>
            <td style="text-align: right">{fmt(s.domains)}</td>
            <td class="muted">{ago(s.last_fetch)}</td>
            <td>
              {#if s.last_error}
                <span class="pill err" title={s.last_error}>error</span>
              {:else if !s.enabled}
                <span class="pill">disabled</span>
              {:else}
                <span class="pill ok">ok</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  <p class="muted" style="font-size: 0.8rem">
    Refresh Now fetches every source immediately. Sources also refresh
    automatically on their configured interval; a failed fetch keeps the
    previously loaded domains.
  </p>
{/if}

<style>
  tr.disabled { opacity: 0.55; }
  .pill.ok { color: var(--ok); border-color: var(--ok); }
  .pill.err { color: var(--danger); border-color: var(--danger); }
  pre {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    overflow: auto;
    font-size: 0.8rem;
  }
</style>

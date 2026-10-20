<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';

  let status = $state(null);
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);

  const isAdmin = getStoredUser()?.role === 'admin';

  // Installed AI model files (fastText starter, MiniLM verifier, tokenizer,
  // centroids) + the shared updater run state.
  let models = $state(null);
  let modelsError = $state(null);
  let modelRun = $state(null); // active/finished model update run
  let modelBusy = $state(false);
  let pollTimer = null;
  const RUNNING = ['preparing', 'downloading', 'installing', 'applying', 'restarting', 'rolling_back'];

  function fmtSize(bytes) {
    if (bytes == null) return '—';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${bytes} B`;
  }

  async function loadModels() {
    modelsError = null;
    try {
      models = await api.aiModelStatus();
      modelRun = models?.state?.phase ? models.state : null;
      // Follow an active run so the button state reflects the server.
      if (RUNNING.includes(modelRun?.phase)) {
        scheduleModelPoll();
      }
    } catch (e) {
      models = null;
      modelsError = formatApiError(e);
    }
  }

  function scheduleModelPoll() {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(async () => {
      try {
        const run = (await api.updateStatus())?.state;
        modelRun = run?.phase ? run : null;
        if (RUNNING.includes(modelRun?.phase)) {
          scheduleModelPoll();
        } else if (modelRun?.phase) {
          // Terminal: surface the result and refresh the file listing.
          notice = modelRun.message;
          await loadModels();
        }
      } catch {
        // The service restarts during apply; the next poll continues.
        scheduleModelPoll();
      }
    }, 2000);
  }

  async function updateModels() {
    modelBusy = true;
    error = null;
    notice = null;
    try {
      await api.aiUpdateModels();
      modelRun = { phase: 'preparing', message: 'Preparing AI model update…' };
      notice = 'AI model update started - see progress below.';
      scheduleModelPoll();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      modelBusy = false;
    }
  }

  onDestroy(() => clearTimeout(pollTimer));

  // Override editor (allow exempt / clear existing override).
  let overrideDomain = $state('');
  let overrideReason = $state('');
  let overrideBusy = $state(false);

  async function load() {
    loading = true;
    error = null;
    try {
      status = await api.aiStatus();
    } catch (e) {
      status = null;
      // 404 means the [ai] section is disabled: an empty state, not a failure.
      error = e.status === 404 ? null : formatApiError(e);
    } finally {
      loading = false;
    }
  }

  async function rescan() {
    notice = null;
    error = null;
    try {
      await api.aiRescan();
      notice = 'Rescan requested - the scanner starts a cycle now.';
      setTimeout(() => {
        notice = null;
        load();
      }, 1500);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function saveOverride(action) {
    const domain = overrideDomain.trim().replace(/\.+$/, '');
    if (!domain) {
      error = 'Enter a domain for the override.';
      return;
    }
    overrideBusy = true;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, action, overrideReason.trim());
      notice =
        action === 'allow'
          ? `${domain} is now AI-exempt.`
          : `Override cleared for ${domain}.`;
      overrideDomain = '';
      overrideReason = '';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      overrideBusy = false;
    }
  }

  // status_counts keys are scanner row statuses; rename for display and keep
  // a stable order. Unknown keys (a future format) still surface.
  function countFor(key) {
    return status?.status_counts?.[key] ?? 0;
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  // Threat categories are lowercase enum values; show them capitalized.
  function title(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  }

  $effect(() => {
    load();
    loadModels();
  });
</script>

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
{:else if !status}
  <div class="card">
    <h3 style="margin: 0 0 10px">AI Subsystem Disabled</h3>
    <p class="muted" style="max-width: 70ch">
      The <code>[ai]</code> section of the configuration is not enabled, so no
      domains are being classified. Enable it to activate the scanner.
    </p>
  </div>
{:else}
  <div class="grid">
    <div class="card stat">
      <div class="muted">Snapshot Domains</div>
      <div class="big">{fmt(status.snapshot_len)}</div>
    </div>
    <div class="card stat">
      <div class="muted">Pending Classification</div>
      <div class="big">{fmt(countFor('pending'))}</div>
    </div>
    <div class="card stat">
      <div class="muted">Classified</div>
      <div class="big">{fmt(countFor('classified'))}</div>
    </div>
    <div class="card stat">
      <div class="muted">Skipped (No Signal)</div>
      <div class="big">{fmt(countFor('skipped'))}</div>
    </div>
  </div>

  <div class="card" style="margin-top: 14px">
    <div class="spread" style="gap: 10px; flex-wrap: wrap">
      <div>
        <h3 style="margin: 0 0 6px">Scanner</h3>
        <span class="muted small">
          Mode <span class="pill">{status.mode}</span> · Backend
          <span class="pill">{status.backend}</span> · {status.workers} Worker{status.workers === 1 ? '' : 's'} ·
          Every {status.scan_interval_secs}s
        </span>
      </div>
      <button onclick={rescan}>Rescan Now</button>
    </div>
  </div>

  <div class="two-col">
    <div class="card">
      <h3 style="margin: 0 0 4px">Auto-Blockable Threats</h3>
      <p class="muted small" style="margin: 0 0 10px">
        Threat-category verdicts that qualify for auto-blocking: classified
        (not skipped/pending), at or above the blocking threshold, and still
        fresh. Content-category verdicts are not counted here.
      </p>
      {#if Object.keys(status.threat_counts || {}).length}
        <table>
          <thead>
            <tr><th>Category</th><th class="num">Domains</th></tr>
          </thead>
          <tbody>
            {#each Object.entries(status.threat_counts) as [category, n] (category)}
              <tr>
                <td><code>{title(category)}</code></td>
                <td class="num">{fmt(n)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No threat verdicts yet.</p>
      {/if}
    </div>

    <div class="card">
      <h3 style="margin: 0 0 10px">Enforcement</h3>
      <table>
        <tbody>
          <tr><td class="muted">Blocking Threshold</td><td class="num">{status.block_threshold}</td></tr>
          <tr><td class="muted">Category Verdict TTL</td><td class="num">{status.category_ttl_secs}s</td></tr>
          <tr><td class="muted">Threat Verdict TTL</td><td class="num">{status.threat_ttl_secs}s</td></tr>
          <tr>
            <td class="muted">Auto-Block Categories</td>
            <td>
              {#if status.auto_block_categories?.length}
                {#each status.auto_block_categories as c, i (c)}
                  <span class="pill">{c}</span>{i < status.auto_block_categories.length - 1 ? ' ' : ''}
                {/each}
              {:else}
                <span class="muted">None</span>
              {/if}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">AI Models</h3>
    <p class="muted help" style="margin: 0 0 10px">
      The bundled classifier and verifier files. Updating downloads the
      models bundle from the latest GitHub release, verifies it, installs the
      files and restarts the service (a brief DNS pause) with automatic
      rollback on failure.
    </p>
    {#if modelsError}
      <p style="color: var(--danger)">{modelsError}</p>
    {:else if models}
      <table>
        <thead>
          <tr><th>File</th><th class="num">Size</th><th>SHA-256</th></tr>
        </thead>
        <tbody>
          {#each models.files as f (f.file)}
            <tr>
              <td><code>{f.file}</code></td>
              <td class="num">{f.present ? fmtSize(f.size) : 'Missing'}</td>
              <td><code class="muted">{f.sha256 ? f.sha256.slice(0, 16) + '…' : '—'}</code></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if modelRun && RUNNING.includes(modelRun.phase)}
      <div style="margin-top: 10px">
        <span class="pill">{modelRun.phase}</span>
        <span class="muted">{modelRun.message} This page resumes after the service restart.</span>
      </div>
    {:else if isAdmin}
      <div class="row" style="margin-top: 12px">
        <button onclick={updateModels} disabled={modelBusy || !models?.models_dir}>
          Update AI Models
        </button>
        <span class="muted">
          {models?.models_dir ? `Installed in ${models.models_dir}` : 'No model directory found (models update unavailable)'}
        </span>
      </div>
    {/if}
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">Domain Override</h3>
    <p class="muted help" style="margin: 0 0 10px">
      <strong>Allow</strong> exempts a domain from every AI verdict (it is
      never auto-blocked). <strong>Clear</strong> removes an existing override
      so the verdict applies again.
    </p>
    <form class="override-row" onsubmit={(e) => { e.preventDefault(); saveOverride('allow'); }}>
      <input
        bind:value={overrideDomain}
        placeholder="Domain, e.g. news.example.com"
        style="flex: 1; min-width: 200px"
      />
      <input
        bind:value={overrideReason}
        placeholder="Reason (Optional)"
        style="flex: 1; min-width: 160px"
      />
      <button type="submit" disabled={overrideBusy}>Allow</button>
      <button
        type="button"
        class="secondary"
        onclick={() => saveOverride('clear')}
        disabled={overrideBusy}
      >Clear Override</button>
    </form>
  </div>
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
  }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }
  .two-col {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 12px;
    margin-top: 14px;
  }
  .override-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
</style>

<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { backendLabel, cleanDomain, duration, percent, titleCase } from '../aiLabels.js';

  // `onOpenSettings(tab)` opens Settings on a tab; null for viewers.
  let { onOpenSettings = null } = $props();

  let status = $state(null);
  // When the scanner is not running: whether Settings has it turned on
  // (it then only needs a restart), or null when unknown.
  let enabledInSettings = $state(null);
  let overrides = $state([]);
  // Enabled filtering groups whose clients the AI never auto-blocks.
  let aiOffGroups = $state([]);
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);

  // Viewers are read-only; with sign-in off there is no stored user at all.
  const isAdmin = getStoredUser()?.role !== 'viewer';

  // Installed AI model files (fastText starter, MiniLM verifier, tokenizer,
  // centroids) + the shared updater run state.
  let models = $state(null);
  let modelsError = $state(null);
  let modelRun = $state(null); // active/finished model update run
  let modelBusy = $state(false);
  // Opt-in auto install of changed model bundles at the update-check cadence
  // (`[updates].auto_refresh_models` in Settings). Only for admins.
  let autoModels = $state(false);
  let autoBusy = $state(false);
  let pollTimer = null;
  // Must match UpdateState::is_running on the server.
  const RUNNING = ['preparing', 'downloading', 'cloning', 'building', 'installing', 'applying', 'restarting', 'rolling_back'];

  function fmtSize(bytes) {
    if (bytes == null) return '-';
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
    if (isAdmin) {
      api
        .config()
        .then((c) => (autoModels = !!c.updates?.auto_refresh_models))
        .catch(() => {});
    }
  }

  async function toggleAutoModels(e) {
    const want = e.target.checked;
    autoBusy = true;
    error = null;
    try {
      // Send the whole [updates] section: the API replaces it as a unit, so
      // omit the other fields would reset them to defaults.
      const current = (await api.config()).updates || {};
      await api.updateSettings({
        updates: {
          enabled: current.enabled ?? true,
          check_interval_secs: current.check_interval_secs ?? 3600,
          auto_refresh_models: want,
        },
      });
      autoModels = want;
      notice = want
        ? 'New AI model bundles will be installed automatically at the Update Checks cadence.'
        : 'AI model bundles will no longer be installed automatically.';
    } catch (err) {
      error = formatApiError(err);
      e.target.checked = !want; // undo the checkbox on failure
    } finally {
      autoBusy = false;
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
      modelRun = { phase: 'preparing', message: 'Preparing AI model update...' };
      notice = 'AI model update started - see progress below.';
      scheduleModelPoll();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      modelBusy = false;
    }
  }

  onDestroy(() => clearTimeout(pollTimer));

  // New exemption form.
  let exemptDomain = $state('');
  let exemptReason = $state('');
  let exemptBusy = $state(false);

  async function load() {
    loading = true;
    error = null;
    try {
      status = await api.aiStatus();
      overrides = (await api.aiOverrides())?.overrides || [];
      api
        .blockingGroups()
        .then((groups) => {
          aiOffGroups = (groups || [])
            .filter((g) => g.enabled && g.ai_blocking === false)
            .map((g) => g.name);
        })
        .catch(() => {});
    } catch (e) {
      status = null;
      // 404 means the scanner is off: an empty state, not a failure.
      error = e.status === 404 ? null : formatApiError(e);
      if (e.status === 404) {
        enabledInSettings = await api
          .config()
          .then((c) => !!c.ai?.enabled)
          .catch(() => null);
      }
    } finally {
      loading = false;
    }
  }

  let scanBusy = $state(false);
  async function rescan() {
    notice = null;
    error = null;
    scanBusy = true;
    try {
      await api.aiRescan();
      notice = 'Scan started. The counts below update when it finishes.';
      setTimeout(load, 3000);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      // Debounce repeated clicks; the scan itself runs in the background.
      setTimeout(() => (scanBusy = false), 3000);
    }
  }

  async function exempt() {
    if (!exemptDomain.trim()) return;
    const domain = cleanDomain(exemptDomain);
    if (!domain) {
      notice = null;
      error = `"${exemptDomain.trim()}" is not a domain name. Enter one such as news.example.com.`;
      return;
    }
    exemptBusy = true;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, 'allow', exemptReason.trim());
      notice = `${domain} and its subdomains are now exempt from AI blocking.`;
      exemptDomain = '';
      exemptReason = '';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      exemptBusy = false;
    }
  }

  async function removeExemption(domain) {
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, 'clear');
      notice = `${domain} is no longer exempt.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function countFor(key) {
    return status?.status_counts?.[key] ?? 0;
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  function when(stamp) {
    if (!stamp) return '-';
    const ms = Date.parse(stamp);
    return Number.isNaN(ms) ? '-' : formatDateTime(ms);
  }

  const enforcing = $derived(status?.mode === 'enforce');
  const blockable = $derived(Object.entries(status?.blockable_counts || {}));
  const blockableTotal = $derived(blockable.reduce((sum, [, n]) => sum + n, 0));
  // The heuristic rules score at most 35%, below any allowed threshold (a
  // verifier behind them corroborates, it does not lift them that far).
  const heuristicOnly = $derived(!!status?.backend?.startsWith('heuristic'));
  // Turned off in Settings while running: nothing is classified or blocked.
  const switchedOff = $derived(status?.enabled === false);

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
    <p class="muted">Loading...</p>
  </div>
{:else if !status}
  <div class="card">
    {#if enabledInSettings}
      <h3 style="margin: 0 0 10px">AI Scanner Starts After a Restart</h3>
      <p class="muted" style="margin: 0">
        The scanner is turned on in Settings → AI Scanner but was off when the
        service started. Restart the service to start it.
      </p>
    {:else}
      <h3 style="margin: 0 0 10px">AI Scanner Is Off</h3>
      <p class="muted" style="margin: 0">
        No domains are being classified. Turn the scanner on in Settings → AI
        Scanner; it starts after the next restart.
      </p>
    {/if}
    {#if onOpenSettings}
      <button class="secondary" style="margin-top: 12px" onclick={() => onOpenSettings('ai')}>Open AI Settings</button>
    {/if}
  </div>
{:else}
  {#if switchedOff}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>The AI scanner is turned off.</strong>
      It is not classifying domains or blocking any. The verdicts below are
      from before; turn it back on in Settings → AI Scanner.
    </div>
  {:else if enforcing && heuristicOnly}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>Nothing can be auto-blocked yet.</strong>
      Enforce mode is on, but the scanner is using its built-in heuristic
      rules, whose verdicts never reach the block threshold. Set a trained
      model in Settings → AI Scanner (see AI Models below) to auto-block.
    </div>
  {/if}

  <div class="grid">
    <div class="card stat" title={enforcing && !switchedOff ? 'Domains the AI is blocking right now' : 'Domains the AI would block in Enforce mode'}>
      <div class="muted">{enforcing && !switchedOff ? 'Auto-Blocked Now' : 'Would Auto-Block'}</div>
      <div class="big">{fmt(enforcing && !switchedOff ? status.snapshot_len : blockableTotal)}</div>
    </div>
    <div class="card stat">
      <div class="muted">Waiting to Classify</div>
      <div class="big">{fmt(countFor('pending'))}</div>
    </div>
    <div class="card stat">
      <div class="muted">Classified</div>
      <div class="big">{fmt(countFor('classified'))}</div>
    </div>
    <div class="card stat" title="No category matched, or the match was below the confidence floor">
      <div class="muted">Skipped (Low or No Signal)</div>
      <div class="big">{fmt(countFor('skipped'))}</div>
    </div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="spread" style="margin-bottom: 10px; gap: 8px; flex-wrap: wrap">
        <h3 style="margin: 0">Scanner</h3>
        <div class="row" style="gap: 8px">
          {#if isAdmin}
            <button onclick={rescan} disabled={scanBusy || switchedOff} title={switchedOff ? 'Turn the scanner on first' : 'Run a scan cycle now instead of waiting for the next one'}>Scan Now</button>
          {/if}
          {#if onOpenSettings}
            <button class="secondary" onclick={() => onOpenSettings('ai')}>Settings</button>
          {/if}
        </div>
      </div>
      <table>
        <tbody>
          <tr>
            <td class="muted">Mode</td>
            <td>
              {#if switchedOff}
                <span class="pill">Off</span>
              {:else}
                <span class="pill" class:ok={enforcing}>
                  {enforcing ? 'Enforce (Auto-Block)' : 'Train (Record Only)'}
                </span>
              {/if}
            </td>
          </tr>
          <tr><td class="muted">Classifier</td><td>{backendLabel(status.backend)}</td></tr>
          <tr><td class="muted">Scans</td><td>Every {duration(status.scan_interval_secs)} · {status.workers} Worker{status.workers === 1 ? '' : 's'}</td></tr>
          <tr><td class="muted">Block Threshold</td><td>{percent(status.block_threshold)} Confidence</td></tr>
          <tr>
            <td class="muted">Auto-Block Categories</td>
            <td>
              {#each status.auto_block_categories || [] as c (c)}
                <span class="pill">{titleCase(c)}</span>{' '}
              {:else}
                <span class="muted">None</span>
              {/each}
            </td>
          </tr>
          <tr>
            <td class="muted">Applies To</td>
            <td>
              {#if aiOffGroups.length}
                Turned off for filtering groups
                {#each aiOffGroups as g (g)}<span class="pill" style="margin-left: 4px">{g}</span>{/each}
              {:else}
                All Clients
              {/if}
              <div class="muted small">Change this per group under Clients → Filtering Groups.</div>
            </td>
          </tr>
          <tr>
            <td class="muted">Verdicts Re-Checked After</td>
            <td>{duration(status.threat_ttl_secs)} (Threats) · {duration(status.category_ttl_secs)} (Other)</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin: 0 0 4px">{enforcing && !switchedOff ? 'Auto-Blocked Domains' : 'Would Auto-Block'}</h3>
      <p class="muted small" style="margin: 0 0 10px">
        Domains with a current verdict in an auto-block category at or above
        the block threshold, minus exempt domains and verdicts the verifier
        disputed{enforcing && !switchedOff ? '' : ': what Enforce mode would block'}.
      </p>
      {#if blockable.length}
        <table>
          <thead>
            <tr><th>Category</th><th class="num">Domains</th></tr>
          </thead>
          <tbody>
            {#each blockable as [category, n] (category)}
              <tr>
                <td>{titleCase(category)}</td>
                <td class="num">{fmt(n)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">None.</p>
      {/if}
    </div>
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">Exempt Domains ({overrides.length})</h3>
    {#if isAdmin}
      <form class="exempt-row" onsubmit={(e) => { e.preventDefault(); exempt(); }}>
        <input bind:value={exemptDomain} placeholder="Domain, e.g. news.example.com" aria-label="Domain to exempt" spellcheck="false" autocapitalize="off" style="flex: 2; min-width: 200px" />
        <input bind:value={exemptReason} placeholder="Reason (Optional)" aria-label="Reason" maxlength="200" style="flex: 1; min-width: 160px" />
        <button type="submit" disabled={exemptBusy || !exemptDomain.trim()}>Exempt</button>
      </form>
    {/if}
    {#if overrides.length}
      <div class="table-wrap" style="margin-top: 12px">
        <table>
          <thead>
            <tr><th>Domain</th><th>Reason</th><th>Added</th>{#if isAdmin}<th class="num">Actions</th>{/if}</tr>
          </thead>
          <tbody>
            {#each overrides as o (o.domain)}
              <tr>
                <td><code>{o.domain}</code></td>
                <td class="muted">{o.reason || '-'}</td>
                <td class="muted">{when(o.created_at)}</td>
                {#if isAdmin}
                  <td class="num"><IconButton icon="delete" variant="danger" label="Remove exemption for {o.domain}" title="Remove the exemption: let the AI block this domain again" onclick={() => removeExemption(o.domain)} /></td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <p class="muted help">
      An exempt domain and its subdomains are never auto-blocked by the AI,
      whatever their verdict. Verdicts are still recorded. You can paste a
      URL; only its domain is used.
    </p>
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">AI Models</h3>
    <p class="muted help" style="margin: 0 0 10px">
      The bundled classifier and verifier files. Updating downloads the
      models bundle from the latest GitHub release, verifies it, installs the
      files and restarts the service (a brief DNS pause) with automatic
      rollback on failure.
    </p>
    {#if isAdmin && models?.models_dir && !modelRun}
      <label class="check auto-row">
        <input
          type="checkbox"
          checked={autoModels}
          disabled={autoBusy}
          onchange={(e) => toggleAutoModels(e)}
        />
        <span>
          Keep AI Models up to Date
          <span class="muted small"> (installs new model bundles automatically with every Update Check; each install restarts the service; also on the Update page)</span>
        </span>
      </label>
    {/if}
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
              <td><code class="muted">{f.sha256 ? f.sha256.slice(0, 16) + '...' : '-'}</code></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if modelRun && RUNNING.includes(modelRun.phase)}
      <div style="margin-top: 10px">
        <span class="pill">{titleCase(modelRun.phase.replace('_', ' '))}</span>
        <span class="muted">{modelRun.message} This page resumes after the service restart.</span>
      </div>
    {:else if isAdmin}
      <div class="row" style="margin-top: 12px">
        <button onclick={updateModels} disabled={modelBusy || !models?.models_dir}>
          Update AI Models
        </button>
        {#if !models?.models_dir}
          <span class="muted">No model directory found (models update unavailable)</span>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
  }
  @media (max-width: 900px) {
    .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  .stat .big { font-size: 1.6rem; font-weight: 700; margin-top: 6px; }
  .two-col {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 12px;
    margin-top: 14px;
  }
  .warn { border-color: var(--warn); }
  .exempt-row { display: flex; gap: 8px; flex-wrap: wrap; }
  .small { font-size: 0.85rem; }
  .auto-row { margin-bottom: 10px; }
</style>

<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { backendLabel, duration, percent, titleCase } from '../aiLabels.js';

  // `onOpenSettings()` opens the AI page's Settings tab and `onOpenThreats()` the
  // AI page's Threats tab; both null for viewers.
  let { onOpenSettings = null, onOpenThreats = null } = $props();

  let status = $state(null);
  // When the scanner is not running: whether Settings has it turned on
  // (it then only needs a restart), or null when unknown.
  let enabledInSettings = $state(null);
  // Enabled filtering groups that override the global mode, split by the
  // override they chose.
  let aiEnforceGroups = $state([]);
  let aiRecordGroups = $state([]);
  const aiOverrides = $derived([
    ...aiEnforceGroups.map((name) => ({ name, label: 'Always enforce' })),
    ...aiRecordGroups.map((name) => ({ name, label: 'Record only' })),
  ]);
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let retraining = $state(false);
  let rollingBack = $state(false);

  // Viewers are read-only; with sign-in off there is no stored user at all.
  const isAdmin = getStoredUser()?.role !== 'viewer';

  // Installed AI model files (fastText starter, MiniLM verifier, tokenizer,
  // centroids) + the shared updater run state.
  let models = $state(null);
  let modelsError = $state(null);
  let modelRun = $state(null); // active/finished model update run
  let modelBusy = $state(false);
  let pollTimer = null;
  // Stops a poll that was in flight when the page closed from scheduling
  // another one (and polling forever in the background).
  let destroyed = false;
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
  }

  function scheduleModelPoll() {
    clearTimeout(pollTimer);
    if (destroyed) return;
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

  let rescanTimer = null;
  onDestroy(() => {
    destroyed = true;
    clearTimeout(pollTimer);
    clearTimeout(rescanTimer);
  });

  // `quiet` refreshes the figures in place (after Scan Now) instead of
  // blanking the page to a loading state.
  async function load(quiet = false) {
    loading = !quiet;
    error = null;
    try {
      status = await api.aiStatus();
      api
        .blockingGroups()
        .then((groups) => {
          const enabled = (groups || []).filter((g) => g.enabled);
          aiEnforceGroups = enabled
            .filter((g) => g.ai_mode === 'enforce')
            .map((g) => g.name);
          aiRecordGroups = enabled
            .filter((g) => g.ai_mode === 'train')
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
      clearTimeout(rescanTimer);
      rescanTimer = setTimeout(() => load(true), 3000);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      // Debounce repeated clicks; the scan itself runs in the background.
      setTimeout(() => (scanBusy = false), 3000);
    }
  }

  function countFor(key) {
    return status?.status_counts?.[key] ?? 0;
  }

  async function setAutoRetrain(value) {
    try {
      await api.updateSettings({ ai: { auto_retrain: value } });
      status = { ...status, auto_retrain: value };
      notice = value
        ? 'Automatic retraining is on: the scanner will rebuild its model from its own verdicts and your corrections.'
        : 'Automatic retraining is off; the current model stays as it is.';
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  async function setVerifier(value) {
    try {
      await api.updateSettings({ ai: { verifier_enabled: value } });
      notice = value
        ? 'The verifier now second-checks every threat: a confident disagreement disputes it, and its agreement lets the AI learn from that verdict.'
        : 'The verifier is off; threats rely on the primary classifier alone.';
      await load(true);
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  async function setTrialNewModels(value) {
    try {
      await api.updateSettings({ ai: { trial_new_models: value } });
      status = { ...status, trial_new_models: value };
      notice = value
        ? 'Scheduled retrains now run in the shadow of the live model and replace it only if they do at least as well.'
        : 'Scheduled retrains now go live straight away; restore the previous model by hand if needed.';
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  // `[updates]` is replaced as a unit by the API, so the whole section is
  // read and sent back with the one field changed.
  async function setAutoRefreshModels(value) {
    try {
      const updates = (await api.config()).updates || {};
      await api.updateSettings({ updates: { ...updates, auto_refresh_models: value } });
      status = { ...status, auto_refresh_models: value };
      notice = value
        ? 'New shipped models will be installed automatically, checked against held-out threats and restored if they do worse.'
        : 'Shipped models are updated only when you choose to.';
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  async function setLearnNegatives(value) {
    try {
      await api.updateSettings({ ai: { learn_negatives: value } });
      status = { ...status, learn_negatives: value };
      notice = value
        ? '\"Not a threat\" corrections will train a benign label. If the model starts missing threats, turn this off and restore the previous model.'
        : '\"Not a threat\" corrections are no longer used as training data; they still stop a block.';
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  async function setFetchPages(value) {
    try {
      await api.updateSettings({ ai: { fetch_pages: value } });
      status = { ...status, fetch_pages: value };
      notice = value
        ? 'Page reading is on: new threat candidates will have their home page fetched from this server and its text recorded with the verdict.'
        : 'Page reading is off; threat verdicts keep the name-only evidence they already have.';
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  async function setPageRule(value) {
    try {
      await api.updateSettings({ ai: { page_rule: value } });
      status = { ...status, page_rule: value };
      notice =
        value === 'decide'
          ? 'Page readings can now raise or cap a threat confidence, so a page that reads as ordinary can stop a name-only block. A site writes its own page, so this can be gamed.'
          : value === 'corroborate'
            ? 'Page readings can now raise a threat confidence, never lower it.'
            : 'Page readings are recorded as evidence only; verdicts are unchanged.';
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    }
  }

  async function rollbackModel(model = 'shared') {
    rollingBack = true;
    error = null;
    notice = null;
    try {
      const result = await api.aiRollback(model);
      notice = result?.message || 'The previous model is in use again.';
      await load(true);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      rollingBack = false;
    }
  }

  async function retrain(model = 'shared') {
    retraining = true;
    error = null;
    notice = null;
    try {
      const result = await api.aiRetrain(model);
      const negatives = result.negatives
        ? `, ${fmt(result.negatives)} from "not a threat" marks`
        : '';
      const unconfirmed = result.unconfirmed
        ? ` ${fmt(result.unconfirmed)} of its own verdicts were left out because nothing independent confirmed them.`
        : '';
      notice = `Retrained from ${fmt(result.examples)} examples across ${fmt(result.labels)} labels (${fmt(result.corrections)} from your corrections${negatives}).${unconfirmed} ${result.message || 'The new model is in use now.'}`;
      await load(true);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      retraining = false;
    }
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  const enforcing = $derived(status?.mode === 'enforce');
  const blockable = $derived(Object.entries(status?.blockable_counts || {}));
  const blockableTotal = $derived(blockable.reduce((sum, [, n]) => sum + n, 0));
  // The heuristic rules score at most 35%, below any allowed threshold (a
  // verifier behind them corroborates, it does not lift them that far).
  // Only the threat channel auto-blocks, so only its pipeline matters: the
  // combined `backend` name starts with the categorizer's.
  const heuristicOnly = $derived(
    !!(status?.threat_backend ?? status?.backend)?.startsWith('heuristic'),
  );
  // Turned off in Settings while running: nothing is classified or blocked.
  const switchedOff = $derived(status?.enabled === false);

  load();
  loadModels();
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
        The scanner is turned on in the Settings tab but was off when the
        service started. Restart the service to start it.
      </p>
    {:else}
      <h3 style="margin: 0 0 10px">AI Scanner Is Off</h3>
      <p class="muted" style="margin: 0">
        No domains are being classified. Turn the scanner on in the Settings
        tab; it starts after the next restart.
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
      It is not classifying domains or blocking any. The classifications and
      threats below are from before; turn it back on in the Settings tab.
    </div>
  {:else if enforcing && heuristicOnly}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>Nothing can be auto-blocked yet.</strong>
      Enforce mode is on, but the scanner is using its built-in heuristic
      rules, whose detections never reach the block threshold. Set a trained
      model (see AI Models below) to auto-block.
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
          <tr>
            <td class="muted">Threat Channel</td>
            <td>
              {backendLabel(status.threat_backend)}
              <span class="pill" title={status.threat_model_dedicated
                ? 'The threat channel runs its own model: every label it reports is a threat'
                : 'Both channels use the shared classifier, so the label list defines threats'}>
                {status.threat_model_dedicated ? 'Own Model' : 'Shared Model'}
              </span>
            </td>
          </tr>
          <tr><td class="muted">Scans</td><td>Every {duration(status.scan_interval_secs)} · {status.workers} Worker{status.workers === 1 ? '' : 's'}</td></tr>
          <tr><td class="muted">Block Threshold</td><td>{percent(status.block_threshold)} Confidence</td></tr>
          <tr>
            <td class="muted">Labels Treated as Threats</td>
            <td>
              {#each status.auto_block_categories || [] as c (c)}
                <span class="pill">{titleCase(c)}</span>{' '}
              {:else}
                <span class="muted">None</span>
              {/each}
              {#if onOpenThreats}
                <button class="secondary" style="padding: 2px 8px; margin-left: 6px" onclick={onOpenThreats}>Change</button>
              {/if}
            </td>
          </tr>
          <tr>
            <td class="muted">Applies To</td>
            <td>
              {#each aiOverrides as o (o.name)}
                <span class="pill" style="margin-right: 4px">{o.name}: {o.label}</span>
              {:else}
                All Clients
              {/each}
              <div class="muted small">Change this per group under Clients → Filtering Groups.</div>
            </td>
          </tr>
          <tr>
            <td class="muted">Re-Checked After</td>
            <td>{duration(status.threat_ttl_secs)} (Threats) · {duration(status.category_ttl_secs)} (Classifications)</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="spread" style="margin-bottom: 4px; gap: 8px; flex-wrap: wrap">
        <h3 style="margin: 0">{enforcing && !switchedOff ? 'Auto-Blocked Domains' : 'Would Auto-Block'}</h3>
        {#if onOpenThreats}
          <button class="secondary" style="padding: 2px 8px" onclick={onOpenThreats}>View Threats</button>
        {/if}
      </div>
      <p class="muted small" style="margin: 0 0 10px">
        {#if status.threat_model_dedicated}
          Detected threats at or above the block threshold, minus exempt
          domains and threats the verifier disputed
        {:else}
          Detected threats whose label is treated as a threat and whose
          confidence is at or above the block threshold, minus exempt domains
          and threats the verifier disputed
        {/if}
        {enforcing && !switchedOff ? '.' : ': what Enforce mode would block.'}
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
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Model Maintenance</h3>
      {#if isAdmin}
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.auto_retrain}
            onchange={(event) => setAutoRetrain(event.currentTarget.checked)}
          />
          <span>Retrain Automatically</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.learn_negatives}
            onchange={(event) => setLearnNegatives(event.currentTarget.checked)}
          />
          <span>Learn "Not a Threat"</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.trial_new_models}
            onchange={(event) => setTrialNewModels(event.currentTarget.checked)}
          />
          <span>Trial New Models First</span>
        </label>
        {#if status.verifier_installed || status.verifier_enabled}
          <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem" title="The MiniLM model second-checks every threat and confirms labels the AI may learn from">
            <input
              type="checkbox"
              style="width: auto"
              checked={!!status.verifier_enabled}
              onchange={(event) => setVerifier(event.currentTarget.checked)}
            />
            <span>Second Opinion (Verifier)</span>
          </label>
        {/if}
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.auto_refresh_models}
            onchange={(event) => setAutoRefreshModels(event.currentTarget.checked)}
          />
          <span>Install New Shipped Models</span>
        </label>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      The scanner rebuilds its classifier from what it has learned: your
      category corrections and mislabelled marks on AI → Threats, plus its own
      verdicts - but only those the shipped reference model, the verifier
      model or the page itself agrees with, so a mistake cannot feed on
      itself - on top of the starter corpus, so labels this network has not
      seen lately are never forgotten. A candidate must hold up on
      corrections and threats it was not trained on and still report every
      threat label. Then, with Trial New Models First on, it runs in the
      shadow of the live model for half the retrain interval without
      answering a single query, and replaces it only if it did at least as
      well on held-out threats, on the threats each finds among the domains
      looked up, on your corrections during the trial and on independently
      confirmed labels. A rejected candidate changes nothing, pauses
      retraining for a while and raises an alert. Retrain Now goes live at
      once. A dedicated threat model is maintained the same way, and the
      verifier's reference is refreshed from your corrections (never from
      the AI's own verdicts, so it stays an independent second opinion).
      With Install New Shipped Models on (the default), new reference models arrive through
      the updater, which checks them against held-out threats too. With Learn
      "Not a Threat" on, your not-a-threat marks become a benign label - a
      negative class can over-generalise, which the trial checks for.
    </p>
    {@render maintained('Shared Classifier', status.learned_model, 'shared')}
    {#if status.learned_threat_model}
      {@render maintained('Threat Model', status.learned_threat_model, 'threat')}
    {/if}
    {#if isAdmin}
      <p class="muted" style="font-size: 0.8rem; margin: 6px 0 0">
        Scheduled retrains run at most every {duration(status.retrain_interval_secs)} when automatic retraining is on.
      </p>
    {/if}
  </div>

  {#snippet maintained(title, m, model)}
    {#if m}
      <div style="border-top: 1px solid var(--border); padding-top: 8px; margin-top: 8px">
        <p style="margin: 0 0 6px; font-size: 0.9rem"><strong>{title}</strong>
          {#if m.active}
            <span class="pill ok">Retrained Model Live</span>
          {:else}
            <span class="pill">Configured Model Live</span>
          {/if}
          {#if m.trial?.ends_at}
            <span class="pill">Candidate on Trial until {formatDateTime(m.trial.ends_at * 1000)}</span>
          {/if}
        </p>
        {#if m.present}
          <p class="muted" style="margin: 0 0 6px; font-size: 0.85rem">
            <code>{m.path}</code>
            {#if m.last?.trained_at}
              - retrained {formatDateTime(Date.parse(m.last.trained_at))}
            {/if}
            {#if m.last}
              from {fmt(m.last.examples)} examples across {fmt(m.last.labels)} labels
              {#if m.last.unconfirmed}({fmt(m.last.unconfirmed)} unconfirmed verdicts left out){/if}
            {/if}
          </p>
        {/if}
        {#if m.trial?.retry_after && m.trial.retry_after * 1000 > Date.now()}
          <p class="muted" style="margin: 0 0 6px; font-size: 0.85rem">
            Retraining paused after a rejected candidate; it resumes {formatDateTime(m.trial.retry_after * 1000)}.
          </p>
        {/if}
        {#if m.trial?.history?.length}
          <details style="margin: 0 0 6px; font-size: 0.85rem">
            <summary class="muted">Trial history ({m.trial.history.length})</summary>
            <ul style="margin: 4px 0 0 18px; padding: 0">
              {#each m.trial.history as entry (entry.at + entry.outcome)}
                <li><span class="muted">{formatDateTime(entry.at * 1000)}</span> - {entry.outcome}</li>
              {/each}
            </ul>
          </details>
        {/if}
        {#if isAdmin}
          <div class="row" style="gap: 8px; flex-wrap: wrap">
            <button class="secondary" onclick={() => retrain(model)} disabled={retraining}>
              {retraining ? 'Retraining...' : 'Retrain Now'}
            </button>
            {#if m.previous}
              <button class="secondary" onclick={() => rollbackModel(model)} disabled={rollingBack} title="Restore the model the last retrain or promotion replaced">
                {rollingBack ? 'Restoring...' : 'Restore Previous Model'}
              </button>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  {/snippet}

  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Page Content</h3>
      {#if isAdmin}
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.fetch_pages}
            onchange={(event) => setFetchPages(event.currentTarget.checked)}
          />
          <span>Read Pages for Threats</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <span>Reading rule</span>
          <select
            value={status.page_rule || 'evidence'}
            onchange={(event) => setPageRule(event.currentTarget.value)}
          >
            <option value="evidence">Evidence only</option>
            <option value="corroborate">Corroborate</option>
            <option value="decide">Decide</option>
          </select>
        </label>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      When a domain is flagged as a threat, ask the site itself what it says:
      its home page is fetched from this server, its title and text read, and a
      one-line note added to the verdict's evidence (visible in Check a Domain).
      With the default rule it is a second opinion for you and nothing more.
      Evidence only records it; Corroborate lets an agreeing page raise the
      threat confidence; Decide also caps it when the page reads as an ordinary
      category with no threat cue on it, which can stop a name-only block. The
      page is written by the site being judged, so a site can game Decide by
      showing harmless text; choose it only if you accept that. A reading below
      {Math.round((status.page_confidence_floor ?? 0.6) * 100)}% confidence is
      ignored by the rule. Fetching leaves this server, so it is off
      unless you turn it on; only threat candidates are read, at most
      {fmt(status.page_candidates_per_scan || 0)} per scan, {fmt(status.page_fetch_timeout_secs || 0)}s
      timeout each. Requests to private, loopback and link-local addresses are
      refused, including through redirects.
    </p>
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">AI Models</h3>
    <p class="muted help" style="margin: 0 0 10px">
      The bundled classifier and verifier files. Updating downloads the
      models bundle from the latest GitHub release, verifies it, installs the
      files and restarts the service (a brief DNS pause) with automatic
      rollback on failure. New model bundles install automatically while
      Keep AI Models up to Date is on (the default) on the Update page.
    </p>
    {#if models?.bundle}
      <p class="muted" style="margin: 0 0 10px">
        Models bundle <code>v{models.bundle.version}</code>{#if models.bundle.installed_at}, installed {formatDateTime(models.bundle.installed_at)}{/if}
      </p>
    {:else if models?.models_dir}
      <p class="muted" style="margin: 0 0 10px">
        These files carry no recorded release (they were installed before
        versions were tracked); the next models update records it.
      </p>
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
        <span class="pill">{titleCase(modelRun.phase)}</span>
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
  .small { font-size: 0.85rem; }
</style>

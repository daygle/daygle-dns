<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { backendLabel, duration, percent, titleCase } from '../aiLabels.js';

  // `onOpenThreats()` opens the AI page's Threats tab; null for viewers.
  let { onOpenThreats = null } = $props();

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

  // One switch saves at a time: a second click while a save is in flight
  // would race it (and the last response would not necessarily win).
  let switching = $state(false);

  // Save one switch, say what it now does, and put the page back the way
  // the server has it if the save fails.
  async function saveSwitch(body, apply, message) {
    if (switching) return;
    switching = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings(body);
      if (apply) status = { ...status, ...apply };
      notice = message;
      if (!apply) await load(true);
    } catch (e) {
      error = formatApiError(e);
      await load(true);
    } finally {
      switching = false;
    }
  }

  // The switches that are plain `ai` settings, with what each one now does.
  const SWITCHES = {
    auto_retrain: [
      'Automatic retraining is on: the scanner will rebuild its model from its own confirmed verdicts, the threat feeds and your corrections.',
      'Automatic retraining is off; the current model stays as it is.',
    ],
    trial_new_models: [
      'Scheduled retrains now run in the shadow of the live model and replace it only if they do at least as well.',
      'Scheduled retrains now go live straight away; restore the previous model by hand if needed.',
    ],
    threat_feeds: [
      'The threat feeds will be downloaded and used to confirm what the AI learns, test every new model and corroborate threats.',
      'The threat feeds are no longer used; the AI relies on its own models, your corrections and the page.',
    ],
    network_evidence: [
      'Threat verdicts are now checked against the threat feeds and how this network uses each domain.',
      'Threat verdicts rely on the classifiers (and the verifier, if on) alone.',
    ],
    learn_negatives: [
      '"Not a threat" corrections will train a benign label. If the model starts missing threats, turn this off and restore the previous model.',
      '"Not a threat" corrections are no longer used as training data; they still stop a block.',
    ],
    fetch_pages: [
      'Page reading is on: new threat candidates will have their home page fetched from this server and its text recorded with the verdict.',
      'Page reading is off; threat verdicts keep the name-only evidence they already have.',
    ],
  };

  function setSwitch(key, value) {
    const [on, off] = SWITCHES[key];
    return saveSwitch({ ai: { [key]: value } }, { [key]: value }, value ? on : off);
  }

  function setVerifier(value) {
    // The verifier's file and the threat channel change on the server, so
    // the page reloads what it reports instead of guessing.
    return saveSwitch(
      { ai: { verifier_enabled: value } },
      null,
      value
        ? 'The verifier now second-checks every threat: a confident disagreement disputes it, and its agreement lets the AI learn from that verdict.'
        : 'The verifier is off; threats rely on the primary classifier and the network evidence.',
    );
  }

  // `[updates]` is replaced as a unit by the API, so the whole section is
  // read and sent back with the one field changed.
  async function setAutoRefreshModels(value) {
    let updates;
    try {
      updates = (await api.config()).updates || {};
    } catch (e) {
      error = formatApiError(e);
      return;
    }
    return saveSwitch(
      { updates: { ...updates, auto_refresh_models: value } },
      { auto_refresh_models: value },
      value
        ? 'New shipped models will be installed automatically, checked against held-out threats and restored if they do worse.'
        : 'Shipped models are updated only when you choose to.',
    );
  }

  function setPageRule(value) {
    return saveSwitch(
      { ai: { page_rule: value } },
      { page_rule: value },
      value === 'decide'
        ? 'Page readings can now raise or cap a threat confidence, so a page that reads as ordinary can stop a name-only block. A site writes its own page, so this can be gamed.'
        : value === 'corroborate'
          ? 'Page readings can now raise a threat confidence, never lower it.'
          : 'Page readings are recorded as evidence only; verdicts are unchanged.',
    );
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
      const intel = result.intel ? `, ${fmt(result.intel)} from the threat feeds` : '';
      const unconfirmed = result.unconfirmed
        ? ` ${fmt(result.unconfirmed)} of its own verdicts were left out because nothing independent confirmed them.`
        : '';
      notice = `Retrained from ${fmt(result.examples)} examples across ${fmt(result.labels)} labels (${fmt(result.corrections)} from your corrections${negatives}${intel}).${unconfirmed} ${result.message || 'The new model is in use now.'}`;
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
  // A threat feed listing corroborates a verdict at blocking confidence, so
  // with feeds downloaded and evidence on, even the heuristic rules can block
  // a listed domain they flagged.
  const feedsCanBlock = $derived(
    !!status?.network_evidence &&
      !!status?.threat_feeds &&
      (status?.threat_feed_status || []).some((f) => f.entries > 0),
  );

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
  </div>
{:else}
  {#if switchedOff}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>The AI scanner is turned off.</strong>
      It is not classifying domains or blocking any. The classifications and
      threats below are from before; turn it back on in the Settings tab.
    </div>
  {:else if enforcing && heuristicOnly && !feedsCanBlock}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>Nothing can be auto-blocked yet.</strong>
      Enforce mode is on, but the scanner is using its built-in heuristic
      rules, whose detections never reach the block threshold on their own.
      Install a trained model (see AI Models below), or turn on the threat
      feeds and evidence checks (Outside Evidence below) so a detection a
      feed confirms can block.
    </div>
  {:else if enforcing && heuristicOnly}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>Only feed-confirmed threats can be auto-blocked.</strong>
      The scanner is using its built-in heuristic rules, so a detection blocks
      only when a threat feed lists the domain. Install a trained model (see
      AI Models below) to block more.
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
          Detected threats at or above the block threshold, minus exempt and
          disputed domains{:else}Detected threats whose label is treated as a
          threat and whose confidence is at or above the block threshold, minus
          exempt and disputed domains{/if}{enforcing && !switchedOff ? '.' : ': what Enforce mode would block.'}
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
            onchange={(event) => setSwitch('auto_retrain', event.currentTarget.checked)}
            disabled={switching}
          />
          <span>Retrain Automatically</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.learn_negatives}
            onchange={(event) => setSwitch('learn_negatives', event.currentTarget.checked)}
            disabled={switching}
          />
          <span>Learn "Not a Threat"</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.trial_new_models}
            onchange={(event) => setSwitch('trial_new_models', event.currentTarget.checked)}
            disabled={switching}
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
              disabled={switching}
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
            disabled={switching}
          />
          <span>Install New Shipped Models</span>
        </label>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 6px">
      The scanner keeps its own model current: it retrains from your
      corrections, the threat feeds and the verdicts something independent
      confirmed, and a new model replaces the live one only after it proves
      at least as good.
    </p>
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">How retraining stays safe</summary>
      <p class="muted help" style="margin: 6px 0 0">
      The scanner rebuilds its classifier from what it has learned: your
      category corrections and mislabelled marks on AI → Threats, plus its own
      verdicts - but only those the shipped reference model (or, with no
      model file, the built-in rules), the verifier model, a threat feed or
      the page itself agrees with, so a mistake cannot feed on itself - plus
      current threat-feed names, on top of the starter corpus, so labels this
      network has not seen lately are never forgotten. A candidate must hold
      up on corrections, threats and threat-feed names it was not trained on,
      flag no more of your established domains, and still report every
      threat label. Then, with Trial New Models First on, it runs in the
      shadow of the live model for half the retrain interval without
      answering a single query, and replaces it only if it did at least as
      well on held-out threats, on the threats each finds among the domains
      looked up, on your corrections during the trial, on independently
      confirmed labels, on held-out threat-feed names and on the established
      domains looked up - so a trial has evidence to judge even when nobody
      filed a correction. A rejected candidate changes nothing, pauses
      retraining for a while and raises an alert. Retrain Now goes live at
      once. A dedicated threat model is maintained the same way, and the
      verifier's reference is refreshed from your corrections (never from
      the AI's own verdicts, so it stays an independent second opinion).
      With Install New Shipped Models on (the default), new reference models arrive through
      the updater, which checks them against held-out threats too. With Learn
      "Not a Threat" on, your not-a-threat marks become a benign label - a
      negative class can over-generalise, which the trial checks for.
      </p>
    </details>
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
      <h3 style="margin: 0">Outside Evidence</h3>
      {#if isAdmin}
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.threat_feeds}
            onchange={(event) => setSwitch('threat_feeds', event.currentTarget.checked)}
            disabled={switching}
          />
          <span>Use Threat Feeds</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.network_evidence}
            onchange={(event) => setSwitch('network_evidence', event.currentTarget.checked)}
            disabled={switching}
          />
          <span>Check Threats Against Evidence</span>
        </label>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 6px">
      Evidence about a domain beyond its name, so the AI does not only check
      itself against a copy of itself. Works without the ONNX verifier.
    </p>
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">What these switches do</summary>
      <p class="muted help" style="margin: 6px 0 0">
      What the AI knows about a domain beyond its name, so it does not only
      check itself against a copy of itself - this works without the ONNX
      verifier. Use Threat Feeds downloads maintained public lists of malware,
      phishing and scam domains (they name domains, never your traffic): their
      names confirm what retraining may learn, are held out to test every new
      model and trial, and train the threat labels. Check Threats Against
      Evidence applies it to each threat verdict: a feed listing corroborates
      it at blocking confidence, a domain {fmt(status.established_clients ?? 3)}+
      clients have used on {fmt(status.established_days ?? 14)}+ days is
      disputed and never blocks on its name, and a machine-generated name
      first seen today is noted. Your exemptions and corrections still win.
      </p>
    </details>
    {#if status.threat_feed_status?.length}
      <table>
        <thead>
          <tr><th>Feed</th><th>Label</th><th class="num">Names</th><th>Updated</th></tr>
        </thead>
        <tbody>
          {#each status.threat_feed_status as feed (feed.id)}
            <tr>
              <td>{feed.source}</td>
              <td>{titleCase(feed.label)}</td>
              <td class="num">{feed.entries ? fmt(feed.entries) : '-'}</td>
              <td>
                {#if feed.updated_at}{formatDateTime(feed.updated_at * 1000)}{:else}<span class="muted">Not yet</span>{/if}
                {#if feed.error}<span style="color: var(--danger)" title={feed.error}> (last attempt failed)</span>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card" style="margin-top: 14px">
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Page Content</h3>
      {#if isAdmin}
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.fetch_pages}
            onchange={(event) => setSwitch('fetch_pages', event.currentTarget.checked)}
            disabled={switching}
          />
          <span>Read Pages for Threats</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <span>Reading rule</span>
          <select
            value={status.page_rule || 'evidence'}
            onchange={(event) => setPageRule(event.currentTarget.value)}
            disabled={switching}
          >
            <option value="evidence">Evidence only</option>
            <option value="corroborate">Corroborate</option>
            <option value="decide">Decide</option>
          </select>
        </label>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 6px">
      When a domain is flagged as a threat, read its home page and record what
      it says with the verdict (visible in Check a Domain). Off unless you
      turn it on, because the fetch leaves this server.
    </p>
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">How the reading rule works</summary>
      <p class="muted help" style="margin: 6px 0 0">
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
      refused, including through redirects. The text of each page read is
      kept to train a page-text model on this server, from pages a threat
      feed lists and pages of domains known to be ordinary; it is used only
      while it beats the built-in phrase list on pages held out of its
      training, and it can add or strengthen a threat reading, never hide one.
      </p>
    </details>
    {#if status.page_model?.last}
      <p class="muted" style="margin: 0; font-size: 0.85rem">
        Page-text model {status.page_model.active ? 'in use' : 'not in use'}:
        trained {formatDateTime(status.page_model.last.trained_at * 1000)} on
        {fmt(status.page_model.last.pages)} pages, {fmt(status.page_model.last.held_out_right)} of
        {fmt(status.page_model.last.held_out)} held-out pages right (phrase list
        {fmt(status.page_model.last.phrase_table_right)}).
      </p>
    {/if}
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
  .how summary { cursor: pointer; font-size: 0.85rem; }
</style>

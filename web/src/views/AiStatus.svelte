<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { backendLabel, duration, formatBytes, isRunning, percent, titleCase } from '../aiLabels.js';

  // `onOpenThreats()` opens the AI page's Threats tab; null for viewers.
  let { onOpenThreats = null } = $props();

  let status = $state(null);
  const readinessLabels = {
    autonomy_off: 'Autonomy is off',
    retraining_off: 'Automatic retraining is off',
    validating: 'Validating a candidate in a shadow trial',
    paused_after_trial: 'Retraining paused after a rejected trial or rollback',
    waiting_for_evidence: 'Waiting for independently validated training evidence',
    build_failed: 'The last candidate build failed a check',
    scheduled: 'Waiting for the next scheduled retraining check',
  };
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

  // Calibration is an action, not a stored setting: fit a map, apply it, or
  // go back to the uncalibrated score.
  let calibration = $state(null);
  let calibrationBusy = $state(false);
  let calibrationError = $state(null);

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

  async function loadModels() {
    modelsError = null;
    try {
      models = await api.aiModelStatus();
      modelRun = models?.state?.phase ? models.state : null;
      // Follow an active run so the button state reflects the server.
      if (isRunning(modelRun?.phase)) {
        scheduleModelPoll();
      }
    } catch (e) {
      models = null;
      modelsError = formatApiError(e);
    }
  }

  // `POLL_ATTEMPTS` bounds a failing poll: the service restarts during
  // apply, and the update service allows that restart up to 90 seconds, so
  // the page keeps retrying for about two minutes before giving up (and
  // stops polling for good instead of polling for as long as it stays open).
  const POLL_EVERY_MS = 2000;
  const POLL_ATTEMPTS = 60;
  function scheduleModelPoll(attempt = 0) {
    clearTimeout(pollTimer);
    if (destroyed) return;
    pollTimer = setTimeout(async () => {
      try {
        const run = (await api.updateStatus())?.state;
        modelRun = run?.phase ? run : null;
        if (isRunning(modelRun?.phase)) {
          scheduleModelPoll();
        } else if (modelRun?.phase) {
          // Terminal: surface the result and refresh the file listing.
          notice = modelRun.message;
          await loadModels();
        }
      } catch {
        if (attempt < POLL_ATTEMPTS) {
          scheduleModelPoll(attempt + 1);
        } else {
          modelRun = null;
          error = 'Lost track of the model update: the server is not answering. Reload the page to see the result.';
        }
      }
    }, POLL_EVERY_MS);
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
    clearTimeout(scanTimer);
    clearTimeout(feedsBusyTimer);
    feedTimers.forEach(clearTimeout);
  });

  // `quiet` refreshes the figures in place (after Scan Now) instead of
  // blanking the page to a loading state.
  let statusRequest = 0;
  async function load(quiet = false) {
    const request = ++statusRequest;
    loading = !quiet;
    error = null;
    try {
      const next = await api.aiStatus();
      if (request !== statusRequest) return;
      status = next;
      loadCalibration();
      api
        .blockingGroups()
        .then((groups) => {
          if (request !== statusRequest) return;
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
      if (request !== statusRequest) return;
      status = null;
      // 404 means the scanner is off: an empty state, not a failure.
      error = e.status === 404 ? null : formatApiError(e);
      if (e.status === 404) {
        const enabled = await api
          .config()
          .then((c) => !!c.ai?.enabled)
          .catch(() => null);
        if (request === statusRequest) enabledInSettings = enabled;
      }
    } finally {
      if (request === statusRequest) loading = false;
    }
  }

  let scanBusy = $state(false);
  let scanTimer = null;
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
      clearTimeout(scanTimer);
      scanTimer = setTimeout(() => (scanBusy = false), 3000);
    }
  }

  // The download runs in the background: re-read the status a few times so
  // the table shows each feed's result as it lands.
  let feedsBusy = $state(false);
  let feedsBusyTimer = null;
  let feedTimers = [];
  async function updateFeeds() {
    notice = null;
    error = null;
    feedsBusy = true;
    try {
      await api.aiUpdateThreatFeeds();
      notice = 'Downloading the threat feeds. The table below updates as each one finishes.';
      feedTimers.forEach(clearTimeout);
      feedTimers = [5000, 15000, 40000].map((ms) => setTimeout(() => load(true), ms));
      clearTimeout(feedsBusyTimer);
      feedsBusyTimer = setTimeout(() => (feedsBusy = false), 15000);
    } catch (e) {
      error = formatApiError(e);
      feedsBusy = false;
    }
  }

  async function loadCalibration() {
    try {
      calibration = await api.aiCalibration();
    } catch {
      calibration = null;
    }
  }

  async function fitCalibration() {
    calibrationBusy = true;
    calibrationError = null;
    notice = null;
    try {
      const result = await api.aiCalibrationFit();
      if (result?.fitted === false || result?.accepted === false) {
        calibrationError = result?.reason || 'The fit was not accepted.';
      } else {
        notice = `Calibration ${result.version} was fitted and recorded on ${result.tuning_samples} tuning and ${result.holdout_samples} held-out sample(s). Apply it to put it in force.`;
      }
      await loadCalibration();
    } catch (e) {
      calibrationError = formatApiError(e);
    } finally {
      calibrationBusy = false;
    }
  }

  async function applyCalibration(version) {
    calibrationBusy = true;
    calibrationError = null;
    notice = null;
    try {
      await api.aiCalibrationApply(version);
      notice = `Calibration ${version} is in force; the stored verdicts were re-scored.`;
      await loadCalibration();
      await load(true);
    } catch (e) {
      calibrationError = formatApiError(e);
    } finally {
      calibrationBusy = false;
    }
  }

  async function disableCalibration() {
    calibrationBusy = true;
    calibrationError = null;
    notice = null;
    try {
      await api.aiCalibrationDisable();
      notice = 'Calibration is off; the assessment score is compared directly, as before.';
      await loadCalibration();
      await load(true);
    } catch (e) {
      calibrationError = formatApiError(e);
    } finally {
      calibrationBusy = false;
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
      'Automatic retraining is on.',
      'Automatic retraining is off. The current model stays as it is.',
    ],
    trial_new_models: [
      'New models are now trialled before they replace the current one.',
      'New models now go live straight away. Use Restore Previous Model if needed.',
    ],
    threat_feeds: [
      'Threat feeds are on. They download within a minute.',
      'Threat feeds are off.',
    ],
    domain_age: [
      'Domain age checks are on.',
      'Domain age checks are off.',
    ],
    network_evidence: [
      'Threats are now checked against the feeds and your network\'s usage.',
      'Evidence checks are off.',
    ],
    learn_negatives: [
      'Your "not a threat" marks will now train the model. Turn this off if it starts missing threats.',
      'Your "not a threat" marks no longer train the model. They still stop blocks.',
    ],
    fetch_pages: [
      'Page reading is on.',
      'Page reading is off.',
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
        ? 'The verifier now double-checks every threat.'
        : 'The verifier is off.',
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
        ? 'New shipped models will install automatically.'
        : 'Shipped models now update only when you choose.',
    );
  }

  function setPageRule(value) {
    return saveSwitch(
      { ai: { page_rule: value } },
      { page_rule: value },
      value === 'decide'
        ? 'Reading rule: Decide. Pages can raise or lower confidence (sites can fool this).'
        : value === 'corroborate'
          ? 'Reading rule: Corroborate. Pages can only raise confidence.'
          : 'Reading rule: Evidence only. Pages are recorded, nothing else changes.',
    );
  }

  async function rollbackModel() {
    rollingBack = true;
    error = null;
    notice = null;
    try {
      const result = await api.aiRollback();
      notice = result?.message || 'The previous model is in use again.';
      await load(true);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      rollingBack = false;
    }
  }

  async function retrain() {
    retraining = true;
    error = null;
    notice = null;
    try {
      const result = await api.aiRetrain();
      notice = `Retrained from ${fmt(result.examples)} examples. The new model is in use now.`;
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
  <div class="card" role="status" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" role="alert" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
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
      No trained model is installed, and the built-in rules are never
      confident enough to block. Install a model (AI Models, below) or turn
      on both Outside Evidence switches.
    </div>
  {:else if enforcing && heuristicOnly}
    <div class="card warn" style="margin-bottom: 14px">
      <strong>Only feed-confirmed threats can be auto-blocked.</strong>
      No trained model is installed, so only threats a feed lists can block.
      Install a model (AI Models, below) to block more.
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
          <tr><td class="muted">Classifier</td><td>{backendLabel(status.threat_backend || status.backend)}</td></tr>
          <tr><td class="muted">Scans</td><td>Every {duration(status.scan_interval_secs)} · {status.workers} Worker{status.workers === 1 ? '' : 's'}</td></tr>
          <tr><td class="muted">Block Threshold</td><td>{percent(status.block_threshold)} Confidence</td></tr>
          <tr>
            <td class="muted">Signal Fusion</td>
            <td>
              {titleCase(status.fusion || 'monitor')}
              <span class="muted small">
                {status.fusion === 'decide'
                  ? '- the fused score is the assessment the gate compares'
                  : status.fusion === 'off'
                    ? '- observations recorded, nothing fused'
                    : '- fused score recorded beside the verdict, not deciding'}
              </span>
            </td>
          </tr>
          <tr>
            <td class="muted">Calibration</td>
            <td>
              {#if status.calibration_version}
                <span class="pill ok">Active</span> {status.calibration_version}
              {:else}
                Identity
                <span class="muted small">- the score is an assessment, not a calibrated probability</span>
              {/if}
            </td>
          </tr>
          <tr>
            <td class="muted">Enforcement Authority</td>
            <td>
              {#if status.authority && status.authority.enabled}
                Per source
                <span class="muted small">
                  (feed: {titleCase(status.authority.feed_stage)}, model: {titleCase(status.authority.model_stage)})
                </span>
              {:else}
                Off
                <span class="muted small">- the mode above decides what may block</span>
              {/if}
            </td>
          </tr>
          <tr>
            <td class="muted">Labels Treated as Threats</td>
            <td>
              {#each status.threat_labels || status.auto_block_categories || [] as c (c)}
                <span class="pill">{titleCase(c)}</span>{' '}
              {:else}
                <span class="muted">None</span>
              {/each}
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
      </div>
      <p class="muted small" style="margin: 0 0 10px">
        Threats at or above the block threshold, not exempt or disputed{enforcing && !switchedOff ? '.' : ' - what Enforce mode would block.'}
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
    <div class="spread" style="margin-bottom: 8px; gap: 8px; flex-wrap: wrap">
      <h3 style="margin: 0">Calibration</h3>
      {#if isAdmin}
        <div class="row" style="gap: 8px">
          <button onclick={fitCalibration} disabled={calibrationBusy}>Fit a Map</button>
          <button class="secondary" onclick={disableCalibration} disabled={calibrationBusy || !calibration?.calibration_active}>Turn Off</button>
        </div>
      {/if}
    </div>
    <p class="muted small" style="margin: 0 0 10px">
      A map turns the assessment score into a calibrated probability. Fitting
      records one and measures it on a held-out fifth of the labelled evidence;
      nothing changes until a map is applied.
    </p>
    {#if calibrationError}
      <p style="color: var(--danger); margin: 0 0 10px">{calibrationError}</p>
    {/if}
    {#if calibration}
      <table>
        <tbody>
          <tr>
            <td class="muted">In Force</td>
            <td>
              {#if calibration.active}
                <span class="pill ok">Active</span> {calibration.active.version}
                {#if calibration.active.metrics}
                  <span class="muted small">
                    - Brier {calibration.active.metrics.brier.toFixed(4)}, ECE {calibration.active.metrics.ece.toFixed(4)} on {calibration.active.metrics.samples} held-out name(s)
                  </span>
                {/if}
              {:else}
                Identity
                <span class="muted small">- the score is an assessment, not a calibrated probability</span>
              {/if}
            </td>
          </tr>
          <tr><td class="muted">Fitted For</td><td><code class="muted">{calibration.live_model}</code></td></tr>
        </tbody>
      </table>
      {#if calibration.candidates?.length}
        <table style="margin-top: 10px">
          <thead>
            <tr>
              <th>Recorded Map</th>
              <th>Fitted For</th>
              <th class="num">Held-Out</th>
              <th class="num">Brier</th>
              <th class="num">ECE</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each calibration.candidates as candidate (candidate.version)}
              <tr>
                <td>
                  <code>{candidate.version}</code>{#if candidate.active} <span class="pill ok">Active</span>{/if}
                </td>
                <td class="muted"><code class="muted">{candidate.source_model}</code></td>
                <td class="num">{candidate.metrics?.samples ?? 0}</td>
                <td class="num">{candidate.metrics ? candidate.metrics.brier.toFixed(4) : '-'}</td>
                <td class="num">{candidate.metrics ? candidate.metrics.ece.toFixed(4) : '-'}</td>
                <td>
                  {#if isAdmin && !candidate.active && candidate.metrics}
                    <button class="secondary" style="padding: 2px 8px" onclick={() => applyCalibration(candidate.version)} disabled={calibrationBusy}>Apply</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">No map has been recorded yet.</p>
      {/if}
      {#if calibration.note}<p class="muted small">{calibration.note}</p>{/if}
    {:else}
      <p class="muted">Calibration status is unavailable.</p>
    {/if}
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
            checked={!!status.trial_new_models || (status.threat_backend || '').startsWith('fasttext-binary')}
            onchange={(event) => setSwitch('trial_new_models', event.currentTarget.checked)}
            disabled={switching || (status.threat_backend || '').startsWith('fasttext-binary')}
          />
          <span>{(status.threat_backend || '').startsWith('fasttext-binary')
            ? 'Binary candidates always run a trial'
            : 'Trial New Models First'}</span>
        </label>
        {#if status.verifier_supported === false}
          <label class="row muted" style="gap: 6px; align-items: center; font-size: 0.85rem" title="This build has no ONNX support. The threat feeds and evidence checks stand in for it.">
            <input type="checkbox" style="width: auto" checked={false} disabled />
            <span>Second Opinion (Verifier) - not in this build</span>
          </label>
        {:else if status.verifier_installed || status.verifier_enabled}
          <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem" title="A second AI model double-checks every threat">
            <input
              type="checkbox"
              style="width: auto"
              checked={!!status.verifier_enabled}
              onchange={(event) => setVerifier(event.currentTarget.checked)}
              disabled={switching}
            />
            <span>Second Opinion (Verifier)</span>
            {#if status.verifier_enabled && status.verifier_running === false}
              <span class="pill" title="Configured, but the threat channel is not running it: check the server log for why the model did not load">Not Running</span>
            {/if}
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
      The AI retrains itself on a schedule. A new model replaces the current
      one only if it proves at least as good.
    </p>
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">How retraining stays safe</summary>
      <ul class="how-list muted">
        <li><strong>Learns from:</strong> your corrections, the threat feeds, and
          its own verdicts only when something independent agrees.</li>
        <li><strong>Tested first:</strong> a new model must still catch held-out
          threats and must not flag domains your network uses every day.</li>
        <li><strong>Trial New Models First:</strong> the new model shadows the
          current one for a while and is only switched in if it did as well.
          A failed model changes nothing and raises an alert.</li>
        <li><strong>Watched after going live:</strong> for 3 days, a new model
          that starts blocking far more, or gets 3 "not a threat" marks, is
          rolled back automatically and you are alerted.</li>
        <li><strong>Learn "Not a Threat":</strong> your "not a threat" marks also
          train the model. Turn off if it starts missing threats.</li>
        <li><strong>Install New Shipped Models:</strong> updated models from new
          releases install automatically, after the same checks.</li>
        <li><strong>Retrain Now</strong> skips the trial and goes live at once;
          <strong>Restore Previous Model</strong> undoes it.</li>
      </ul>
    </details>
    {#if status.autonomy_readiness}
      {@const readiness = status.autonomy_readiness}
      <section aria-label="Learning and enforcement progress" style="margin: 12px 0">
        <p><strong>{readinessLabels[readiness.state] || 'Learning status unavailable'}</strong></p>
        {#if ['waiting_for_evidence', 'build_failed'].includes(readiness.state) && readiness.last_attempt?.detail}
          <p class="muted">{readiness.last_attempt.detail}</p>
        {/if}
        {#if readiness.state === 'paused_after_trial' && status.learned_model?.trial?.last_outcome}
          <p class="muted">{status.learned_model.trial.last_outcome}</p>
        {/if}
        {#if readiness.enforcement_holds.global_record_only}
          <p class="muted">The default AI mode is Train. Filtering group overrides can change that mode.</p>
        {/if}
        {#if readiness.enforcement_holds.binary_starter}
          <p class="muted">Starter name findings stay in monitor mode until a candidate passes validation.</p>
        {/if}
        {#if status.monitor_page_discovery && readiness.enforcement_holds.page_policy}
          <p class="muted">Page findings are held below enforcement by the current page settings.</p>
        {/if}
        {#if readiness.authority?.length}
          <ul style="padding-left: 18px">
            {#each readiness.authority as decision (decision.source)}
              <li>
                <strong>{titleCase(decision.source)} · {titleCase(decision.effective)}</strong>
                <span class="muted">(configured {readiness.advancement ? 'ceiling' : 'stage'} {titleCase(decision.configured)})</span>
                <div class="muted">{decision.reason}</div>
                {#if decision.next_review_target != null}
                  <div class="muted">
                    Current scoring version: {fmt(decision.confirmed_reviews + decision.corrected_reviews)}
                    of {fmt(decision.next_review_target)} reviews toward the next stage.
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    {/if}
    {@render maintained('Classifier', status.learned_model)}
    {#if isAdmin}
      <p class="muted" style="font-size: 0.8rem; margin: 6px 0 0">
        Scheduled retrains run at most every {duration(status.retrain_interval_secs)} when automatic retraining is on.
      </p>
    {/if}
  </div>

  {#snippet maintained(title, m)}
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
          {#if m.watch?.until}
            <span class="pill" title="This model went live on its own. If it blocks far more than before, or you mark 3 of its new detections 'not a threat', the previous model comes back automatically.">Watched until {formatDateTime(m.watch.until * 1000)}</span>
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
            <button class="secondary" onclick={retrain} disabled={retraining}>
              {retraining ? 'Retraining...' : 'Retrain Now'}
            </button>
            {#if m.previous}
              <button class="secondary" onclick={rollbackModel} disabled={rollingBack} title="Restore the model the last retrain or promotion replaced">
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
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <input
            type="checkbox"
            style="width: auto"
            checked={!!status.domain_age}
            onchange={(event) => setSwitch('domain_age', event.currentTarget.checked)}
            disabled={switching}
          />
          <span>Check Domain Age</span>
        </label>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 6px">
      Checks threats against more than the domain name. Works without the
      ONNX verifier.
    </p>
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">What these switches do</summary>
      <ul class="how-list muted">
        <li><strong>Use Threat Feeds:</strong> downloads public lists of known
          malware, phishing and scam domains, and of the most popular sites
          (your traffic is never sent). They help the AI learn and test new
          models.</li>
        <li><strong>Check Threats Against Evidence:</strong>
          <ul>
            <li>A domain on a threat feed is confirmed and can block.</li>
            <li>A popular site, or a domain {fmt(status.established_clients ?? 3)}+
              devices have used on {fmt(status.established_days ?? 14)}+ days,
              is marked disputed and is never blocked on its name alone.</li>
            <li>A random-looking name first seen today is noted.</li>
          </ul>
        </li>
        <li><strong>Check Domain Age:</strong> looks up when a flagged domain
          was registered. One registered in the last 2 weeks and strongly
          flagged can block; one registered years ago is trusted a little
          more. The registry sees which domain was asked about, not who asked.</li>
        <li>Your exemptions and corrections always win.</li>
      </ul>
    </details>
    {#if status.threat_feed_status?.length}
      <table>
        <thead>
          <tr><th>List</th><th>Label</th><th class="num">Names</th><th>Updated</th></tr>
        </thead>
        <tbody>
          {#each status.threat_feed_status as feed (feed.id)}
            <tr>
              <td>{feed.source}</td>
              <td>{titleCase(feed.label)}</td>
              <td class="num">{feed.entries ? fmt(feed.entries) : '-'}</td>
              <td>
                {#if feed.updated_at}{formatDateTime(feed.updated_at * 1000)}{:else}<span class="muted">Not yet</span>{/if}
                {#if feed.stale}<span style="color: var(--danger)"> (not updating - check internet access)</span>{:else if feed.error}<span class="muted"> (last attempt failed, retrying)</span>{/if}
                {#if feed.error}<div class="muted" style="font-size: 12px; overflow-wrap: anywhere">{feed.error}</div>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if isAdmin}
      <div class="row" style="margin-top: 10px; gap: 10px; align-items: center; flex-wrap: wrap">
        <button class="secondary" onclick={updateFeeds} disabled={feedsBusy || !status.threat_feeds}>
          {feedsBusy ? 'Updating...' : 'Update Now'}
        </button>
        <span class="muted" style="font-size: 12px">
          Feeds refresh every 12 hours by themselves. A failed download is retried after 5 minutes if the site could not be reached, otherwise hourly.
        </span>
      </div>
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
          <span>Read Pages</span>
        </label>
        <label class="row" style="gap: 6px; align-items: center; font-size: 0.85rem">
          <span>Reading rule</span>
          <select
            value={status.page_rule || 'corroborate'}
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
      Reads the home page of each flagged domain and records what it says,
      and categorizes domains the AI is unsure of from their page. On by
      default; turn it off if this server must not contact the sites your
      network visits.
    </p>
    {#if onOpenThreats}
      <p class="muted help" style="margin: 0 0 6px">
        To see what the AI made of one domain, check it under
        <button type="button" class="link" onclick={onOpenThreats}>Check a Domain</button>
        on the Threats tab.
      </p>
    {/if}
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">How the reading rule works</summary>
      <ul class="how-list muted">
        <li><strong>Evidence only:</strong> records what the page says.
          Nothing else changes.</li>
        <li><strong>Corroborate</strong> (default): a page that looks like a threat
          raises the confidence. It never lowers it.</li>
        <li><strong>Decide:</strong> also lowers the confidence when the page
          looks ordinary. The site writes its own page, so it can fool this.</li>
        <li>Readings below {Math.round((status.page_confidence_floor ?? 0.6) * 100)}%
          confidence are ignored. Up to {fmt(status.page_candidates_per_scan || 0)}
          pages per scan, {fmt(status.page_fetch_timeout_secs || 0)}s each;
          private and local addresses are never fetched.</li>
        <li>Page text is kept to train a page model that learns what threat
          pages look like. It can only strengthen a threat reading, never hide one.</li>
        <li>A domain the AI is unsure how to categorize (below 50%) takes the
          category its page clearly states. Those labels are never trained on,
          and never make or clear a threat.</li>
      </ul>
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
      The model files the AI uses. Updating downloads the latest release,
      checks it and restarts the service (a brief DNS pause); a failed update
      is rolled back automatically.
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
              <td class="num">{f.present ? formatBytes(f.size) : 'Missing'}</td>
              <td><code class="muted">{f.sha256 ? f.sha256.slice(0, 16) + '...' : '-'}</code></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if modelRun && isRunning(modelRun.phase)}
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
  /* One column on a phone: two 1.6rem figures side by side wrap their
     captions onto three lines. */
  @media (max-width: 560px) {
    .grid { grid-template-columns: 1fr; }
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font: inherit;
    text-decoration: underline;
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
  .how-list { margin: 6px 0 0; padding-left: 18px; font-size: 0.85rem; line-height: 1.45; }
  .how-list li { margin: 3px 0; }
  .how-list ul { margin: 3px 0 0; padding-left: 18px; }
</style>

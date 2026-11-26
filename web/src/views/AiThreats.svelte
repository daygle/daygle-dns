<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDate } from '../datetime.svelte.js';
  import { pageRuleLabel, percent, stampTime, titleCase } from '../aiLabels.js';
  import ColumnPicker from '../ColumnPicker.svelte';
  import { isHidden } from '../columns.svelte.js';
  import AiExemptionDialog from './AiExemptionDialog.svelte';
  import AiCorrectionDialog from './AiCorrectionDialog.svelte';

  const COLUMNS = [
    { key: 'domain', label: 'Domain', locked: true },
    { key: 'category', label: 'Category' },
    { key: 'state', label: 'State' },
    { key: 'decision', label: 'Decision' },
    { key: 'confidence', label: 'Confidence' },
    { key: 'score', label: 'Threat Score' },
    { key: 'signals', label: 'Signals' },
    { key: 'reason', label: 'Why' },
    { key: 'seen', label: 'Seen' },
    { key: 'evidence', label: 'Evidence' },
    { key: 're-check', label: 'Re-Check' },
  ];
  const show = (key) => !isHidden('ai-threats', key);
  // The scored inputs under a Signal in the Signals column and in the
  // explain panel. Each is scored on its own; none of them blocks.
  const SIGNAL_LABELS = {
    model: 'Model',
    feed: 'Feed',
    popular: 'Popular',
    established: 'Established',
    age: 'Age',
    name: 'Name',
  };
  const signalLabel = (key) => SIGNAL_LABELS[key] || key;

  const PER_PAGE = 50;
  const SEVERITY_FILTERS = [
    { value: '', label: 'All Severities' },
    { value: 'threat', label: 'Threat' },
    { value: 'disputed', label: 'Disputed' },
  ];
  const EXEMPTION_FILTERS = [
    { value: '', label: 'All Threats' },
    { value: 'exempt', label: 'Exempt' },
    { value: 'not_exempt', label: 'Not Exempt' },
  ];

  let rows = $state([]);
  let total = $state(0);
  let page = $state(1); // 1-based; mirrors the server's clamped parameter
  let search = $state('');
  let categoryFilter = $state('');
  let categories = $state([]);
  // The labels treated as threats (edited here) and the labels the loaded
  // model can emit, for the "not in the loaded model" hint.
  let threatLabels = $state([]);
  // The list as last saved, and how many stored verdicts each label carries:
  // together they say what a save would delete before it happens.
  let savedLabels = $state([]);
  // The families forced off, kept across saves: a label unticked here joins
  // them, and a family removed in an earlier visit stays off.
  let removalLabels = $state([]);
  let threatCounts = $state({});
  let modelLabels = $state([]);
  let savingLabels = $state(false);
  let labelsNotice = $state(null);
  let labelsError = $state(null);
  // Text fallback: with the scanner off there is no model to list labels
  // from, but the saved list can still be edited for when it is turned on.
  let labelsText = $state('');
  // "Not a threat" corrections, and the explain-this-domain panel.
  let correctionDomain = $state(null);
  let explainInput = $state('');
  let explainResult = $state(null);
  let explainError = $state(null);
  let explaining = $state(false);
  let exporting = $state('');
  let severityFilter = $state('');
  let exemptionFilter = $state('');
  let loading = $state(true);
  let error = $state(null);
  let notice = $state(null);
  let exemptionDomain = $state(null);
  let disabled = $state(false); // true when the scanner is off (404)

  // Viewers are read-only (the server refuses their exemption changes);
  // with sign-in off there is no stored user at all.
  const isAdmin = getStoredUser()?.role !== 'viewer';

  // The labels that count as threats: the built-in families minus the
  // removals, plus the listed labels. The status endpoint reports that set;
  // fall back to computing it when only the list and removals are known.
  function effectiveThreatLabels(effective, list, removals) {
    if (Array.isArray(effective)) return [...effective];
    const off = (removals || []).map((l) => l.toLowerCase());
    return (list || []).filter((l) => !off.includes(l.toLowerCase()));
  }

  async function loadCategories() {
    try {
      const status = await api.aiStatus();
      modelLabels = [...new Set(status?.backend_categories || [])].sort();
      threatLabels = effectiveThreatLabels(
        status?.threat_labels,
        status?.auto_block_categories,
        status?.auto_block_removals,
      );
      removalLabels = [...(status?.auto_block_removals || [])].map((l) => l.toLowerCase());
      savedLabels = [...threatLabels];
      threatCounts = status?.threat_counts || {};
      labelsText = threatLabels.join(', ');
      categories = modelLabels;
    } catch {
      modelLabels = [];
      categories = [];
      threatCounts = {};
      // 404: the scanner is off. The saved list still lives in the config.
      try {
        const config = await api.config();
        threatLabels = effectiveThreatLabels(
          config?.ai?.threat_labels,
          config?.ai?.auto_block_categories,
          config?.ai?.auto_block_removals,
        );
        removalLabels = [...(config?.ai?.auto_block_removals || [])].map((l) => l.toLowerCase());
        savedLabels = [...threatLabels];
        labelsText = threatLabels.join(', ');
      } catch {
        threatLabels = [];
        savedLabels = [];
      }
    }
  }

  // The labels unticked since the list was loaded. Saving deletes their stored
  // threat verdicts, so the count is shown before Save Labels is used.
  const removedLabels = $derived(
    savedLabels.filter((label) => !threatLabels.includes(label)),
  );
  const removedVerdicts = $derived(
    removedLabels.map((label) => ({
      label,
      verdicts: Number(threatCounts[label.toLowerCase()] || 0),
    })),
  );
  const removedVerdictTotal = $derived(
    removedVerdicts.reduce((sum, item) => sum + item.verdicts, 0),
  );
  const removedVerdictDetail = $derived(
    removedVerdicts
      .filter((item) => item.verdicts > 0)
      .map((item) => `${titleCase(item.label)} (${fmt(item.verdicts)})`)
      .join(', '),
  );

  // The model's labels plus any already chosen that it no longer lists, so a
  // label set under another model can still be seen and unticked.
  const labelChoices = $derived([...new Set([...modelLabels, ...threatLabels])].sort());

  function toggleThreatLabel(label) {
    threatLabels = threatLabels.includes(label)
      ? threatLabels.filter((l) => l !== label)
      : [...threatLabels, label];
  }

  async function saveThreatLabels(list = threatLabels) {
    savingLabels = true;
    labelsNotice = null;
    labelsError = null;
    try {
      // Unticking is expressed as a removal as well as by dropping the label
      // from the list: a built-in family the list still named (or one the
      // defaults name) stays off because a removal wins.
      const next = [...list];
      const lowered = next.map((l) => l.toLowerCase());
      const withdrawn = savedLabels
        .map((l) => l.toLowerCase())
        .filter((label) => !lowered.includes(label));
      const removals = [...new Set([...removalLabels, ...withdrawn])].filter(
        (label) => !lowered.includes(label),
      );
      await api.updateSettings({
        ai: { auto_block_categories: next, auto_block_removals: removals },
      });
      labelsNotice = 'Threat labels saved and applied live.';
      await Promise.all([loadCategories(), load()]);
    } catch (e) {
      labelsError = formatApiError(e);
    } finally {
      savingLabels = false;
    }
  }

  function qs() {
    const params = new URLSearchParams();
    if (search.trim()) params.set('q', search.trim());
    if (categoryFilter.trim()) params.set('category', categoryFilter.trim());
    if (severityFilter) params.set('severity', severityFilter);
    if (exemptionFilter) params.set('exemption', exemptionFilter);
    params.set('page', String(page));
    params.set('per_page', String(PER_PAGE));
    return params.toString();
  }

  // Only the newest request may update the table: a slow response for an
  // old filter must not overwrite the one for the filter now shown.
  let requestSeq = 0;

  async function load() {
    const seq = ++requestSeq;
    loading = rows.length === 0;
    error = null;
    try {
      const data = await api.aiThreats(qs());
      if (seq !== requestSeq) return;
      rows = data.entries || [];
      total = data.total || 0;
      disabled = false;
      page = data.page || page;
      // Past the end (verdicts expired or were exempted since the page
      // was opened): show the last page instead of an empty one.
      if (!rows.length && total > 0 && page > 1) {
        page = pages();
        return load();
      }
    } catch (e) {
      if (seq !== requestSeq) return;
      rows = [];
      total = 0;
      // 404 means the scanner is off: an empty state, not a failure.
      if (e.status === 404) {
        disabled = true;
      } else {
        error = formatApiError(e);
      }
    } finally {
      if (seq === requestSeq) loading = false;
    }
  }

  function goPage(next) {
    page = Math.max(1, page + next);
    load();
  }

  function setExempt(domain, exempt) {
    if (exempt) {
      exemptionDomain = domain;
      return;
    }
    applyExemption(domain, false, '');
  }

  async function applyExemption(domain, exempt, reason) {
    exemptionDomain = null;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, exempt ? 'allow' : 'clear', reason);
      notice = exempt
        ? `${domain} and its subdomains are now exempt from AI blocking.`
        : `${domain} is no longer exempt.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Hand `text` to the browser as a download. The link is attached for the
  // click (Firefox ignores clicks on detached links) and the object URL is
  // revoked afterwards: revoking it in the same tick can cancel the download
  // before it starts, as the other export views already allow for.
  function saveText(text, type, filename) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function exportThreats(format) {
    exporting = format;
    error = null;
    notice = null;
    try {
      const text = await api.aiThreatsExport(format);
      saveText(
        text,
        'text/plain;charset=utf-8',
        format === 'list' ? 'ai-threats.txt' : 'ai-threats.csv',
      );
      notice = `Exported ${format === 'list' ? 'the plain domain list' : 'the CSV'} of active threats.`;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      exporting = '';
    }
  }

  async function exportCorrections() {
    // Shares `exporting` with the threat exports: a second click while the
    // first download is being built would produce two files.
    exporting = 'corrections';
    notice = null;
    error = null;
    try {
      const text = await api.aiCorrections('csv');
      saveText(text, 'text/csv;charset=utf-8', 'ai-corrections.csv');
      notice = 'Exported your corrections.';
    } catch (e) {
      error = formatApiError(e);
    } finally {
      exporting = '';
    }
  }

  async function runExplain() {
    const domain = explainInput.trim();
    if (!domain) return;
    explaining = true;
    explainError = null;
    explainResult = null;
    try {
      explainResult = await api.aiExplain(domain);
    } catch (e) {
      explainError = formatApiError(e);
    } finally {
      explaining = false;
    }
  }

  async function applyCorrection(domain, reason, category) {
    correctionDomain = null;
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, 'not_threat', reason);
      if (category) await api.aiOverride(domain, 'category', '', category);
      notice = `${domain} is marked not a threat${category ? ` and relabelled as ${titleCase(category)}` : ''}. It no longer blocks.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  // Drop the operator's label: the AI's own verdict decides again.
  async function clearLabel(domain) {
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, 'clear_category');
      notice = `${domain} no longer carries your label; the AI decides again.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function restoreThreat(domain) {
    notice = null;
    error = null;
    try {
      await api.aiOverride(domain, 'clear');
      notice = `${domain} is treated as a threat again.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function pages() {
    return Math.max(1, Math.ceil(total / PER_PAGE));
  }

  // Threshold trials: the model's version and the threshold are recorded
  // together, so what a trial measured can always be read back, and undoing
  // one puts back only the threshold. Nothing here changes enforcement until
  // Apply is clicked on a trial that passed.
  let threshold = $state(null);
  let trialBusy = $state('');
  let trialNotice = $state(null);
  let trialError = $state(null);
  const inForce = $derived(threshold?.in_force || null);

  async function loadThreshold() {
    try {
      threshold = await api.aiThreshold();
    } catch {
      // The scanner is off (404): there is no threshold to tune.
      threshold = null;
    }
  }

  async function runTrial() {
    trialBusy = 'run';
    trialNotice = null;
    trialError = null;
    try {
      const result = await api.aiThresholdTrial();
      trialNotice = result.message
        || `Trial #${result.trial.id} recorded. Nothing was applied.`;
      await loadThreshold();
    } catch (e) {
      trialError = formatApiError(e);
    } finally {
      trialBusy = '';
    }
  }

  async function applyTrial(trial) {
    if (!confirm(`Set the block threshold to ${percent(trial.candidate)}? The model stays ${trial.model}.`)) return;
    trialBusy = `apply-${trial.id}`;
    trialNotice = null;
    trialError = null;
    try {
      const result = await api.aiThresholdApply(trial.id);
      trialNotice = result.message;
      await loadThreshold();
      await load();
    } catch (e) {
      trialError = formatApiError(e);
    } finally {
      trialBusy = '';
    }
  }

  async function rollbackTrial(trial) {
    trialBusy = `rollback-${trial.id}`;
    trialNotice = null;
    trialError = null;
    try {
      const result = await api.aiThresholdRollback(trial.id);
      trialNotice = result.message;
      await loadThreshold();
      await load();
    } catch (e) {
      trialError = formatApiError(e);
    } finally {
      trialBusy = '';
    }
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  // Reload on mount and whenever the search box changes (back to page 1,
  // since the filter changed the list). Typing waits for a pause.
  let searchTimer;
  let firstLoad = true;
  loadCategories();
  loadThreshold();

  $effect(() => {
    search;
    categoryFilter;
    severityFilter;
    exemptionFilter;
    clearTimeout(searchTimer);
    // The first load runs at once; only later changes wait for a pause.
    searchTimer = setTimeout(() => {
      page = 1;
      load();
    }, firstLoad ? 0 : 250);
    firstLoad = false;
    return () => clearTimeout(searchTimer);
  });
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
{:else if disabled}
  <div class="card">
    <h3 style="margin: 0 0 10px">AI Scanner Is Off</h3>
    <p class="muted" style="margin: 0">
      There are no threats. Turn the scanner on in the Settings tab; it
      starts after the next restart.
    </p>
  </div>

  {#if isAdmin}
    <div class="card" style="margin-top: 14px">
      <h3 style="margin: 0 0 8px">Labels Treated as Threats</h3>
      <p class="muted help" style="margin: 0 0 8px">
        The scanner is off, so type the labels instead, separated by commas.
        They apply when it runs again.
      </p>
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input bind:value={labelsText} placeholder="malware, phishing, scam" style="flex: 1; min-width: 200px" />
        <button onclick={() => saveThreatLabels(labelsText.split(',').map((l) => l.trim().toLowerCase()).filter(Boolean))} disabled={savingLabels}>
          {savingLabels ? 'Saving...' : 'Save Labels'}
        </button>
      </div>
      {#if labelsNotice}<p class="muted" style="color: var(--ok); margin: 8px 0 0">{labelsNotice}</p>{/if}
      {#if labelsError}<p class="dialog-error" style="margin: 8px 0 0">{labelsError}</p>{/if}
    </div>
  {/if}
{:else}
  <div class="card" style="margin-bottom: 14px">
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Labels Treated as Threats</h3>
      {#if isAdmin}
        <button onclick={() => saveThreatLabels()} disabled={savingLabels}>
          {savingLabels ? 'Saving...' : 'Save Labels'}
        </button>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      Malware, phishing and scam are threats unless you untick them. Only
      ticked labels count as threats: in Enforce mode they block once
      confident enough, and unticked labels never block.
    </p>
    {#if labelsNotice}<p class="muted" style="color: var(--ok); margin: 0 0 8px">{labelsNotice}</p>{/if}
    {#if labelsError}<p class="dialog-error">{labelsError}</p>{/if}
    {#if removedLabels.length}
      {#if removedVerdictTotal > 0}
        <p class="warn" role="alert">
          Saving deletes {fmt(removedVerdictTotal)} stored threat
          verdict{removedVerdictTotal === 1 ? '' : 's'}: {removedVerdictDetail}.
          They do not come back if you tick the label again.
        </p>
      {:else}
        <p class="muted small" style="margin: 0 0 8px">
          Saving removes {removedLabels.map((label) => titleCase(label)).join(', ')};
          no stored threat verdicts carry
          {removedLabels.length === 1 ? 'that label' : 'those labels'}, so nothing is deleted.
        </p>
      {/if}
    {/if}
    {#if labelChoices.length}
      <div class="labels">
        {#each labelChoices as label (label)}
          <label class="check">
            <input
              type="checkbox"
              checked={threatLabels.includes(label)}
              onchange={() => toggleThreatLabel(label)}
              disabled={!isAdmin}
            />
            <span>{titleCase(label)}{#if !modelLabels.includes(label)}<span class="muted"> (not in the loaded model)</span>{/if}</span>
          </label>
        {/each}
      </div>
    {:else}
      <p class="muted" style="margin: 0">No labels to choose from: the scanner has no model loaded.</p>
    {/if}
  </div>


  {#if threshold}
    <div class="card" style="margin-bottom: 14px">
      <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
        <h3 style="margin: 0">Threshold Trials</h3>
        {#if isAdmin && threshold.model}
          <button onclick={runTrial} disabled={!!trialBusy}>
            {trialBusy === 'run' ? 'Tuning...' : 'Run Trial'}
          </button>
        {/if}
      </div>
      <p class="muted help" style="margin: 0 0 10px">
        A trial keeps the lowest block threshold whose false-positive rate on
        established and unseen domains meets the target
        ({percent(threshold.fpr_target)}), then checks that threshold on a
        held-out half of the evidence. The threshold is chosen by false
        positives, never by overall accuracy. A trial is recorded with the
        model it measured and changes nothing by itself.
      </p>
      <div class="row" style="gap: 8px; flex-wrap: wrap; align-items: center">
        <span class="muted small">
          Block threshold {percent(threshold.block_threshold)}, model
          <code title={threshold.model || 'built in'}>{threshold.model || 'built in'}</code>
        </span>
        {#if inForce}
          <span class="pill ok tag" title="Applied from a threshold trial; the model was not changed">
            Trial #{inForce.id} In Force
          </span>
        {/if}
      </div>
      {#if trialNotice}<p class="muted" style="color: var(--ok); margin: 8px 0 0">{trialNotice}</p>{/if}
      {#if trialError}<p class="dialog-error" style="margin: 8px 0 0">{trialError}</p>{/if}
      {#if threshold.trials.length}
        <div class="table-wrap" style="margin-top: 10px">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Model</th>
                <th class="num">Threshold</th>
                <th class="num" title="The false-positive target the threshold was chosen against">Target</th>
                <th title="Passed: the held-out half stayed within the target">Result</th>
                {#if isAdmin}<th class="num">Actions</th>{/if}
              </tr>
            </thead>
            <tbody>
              {#each threshold.trials as t (t.id)}
                <tr>
                  <td class="muted nowrap">{stampTime(t.created_at, formatDate)}</td>
                  <td class="muted evidence" title={t.model || 'built in'}>{t.model || 'built in'}</td>
                  <td class="num" title={t.passed ? '' : t.report?.summary || ''}>
                    {percent(t.base_threshold)} → {percent(t.candidate)}
                  </td>
                  <td class="num">{percent(t.fpr_target)}</td>
                  <td>
                    {#if t.in_force}
                      <span class="pill ok tag">In Force</span>
                    {:else if t.passed}
                      <span class="pill" title="Passed on the held-out half; not applied">Passed</span>
                    {:else}
                      <span class="pill err" title={t.report?.summary || 'Did not keep the target on the held-out half'}>Failed</span>
                    {/if}
                    {#if t.restored_threshold != null}
                      <div class="muted" style="font-size: 0.75rem">Undone: back to {percent(t.restored_threshold)}</div>
                    {/if}
                  </td>
                  {#if isAdmin}
                    <td class="num">
                      {#if t.in_force}
                        <button class="secondary" style="padding: 2px 8px; font-size: 0.75rem" title="Put back the threshold this trial replaced; the model is left alone" onclick={() => rollbackTrial(t)} disabled={!!trialBusy}>
                          {trialBusy === `rollback-${t.id}` ? 'Undoing...' : 'Undo Threshold'}
                        </button>
                      {:else if t.passed}
                        <button class="secondary" style="padding: 2px 8px; font-size: 0.75rem" title="Use this trial's threshold; the model is left alone" onclick={() => applyTrial(t)} disabled={!!trialBusy}>
                          {trialBusy === `apply-${t.id}` ? 'Applying...' : 'Apply Threshold'}
                        </button>
                      {:else}
                        <span class="muted">-</span>
                      {/if}
                    </td>
                  {/if}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="muted small" style="margin: 10px 0 0">No trials recorded yet.</p>
      {/if}
    </div>
  {/if}

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 8px">Check a Domain</h3>
    <p class="muted help" style="margin: 0 0 10px">
      Enter a domain to see whether it is blocked, and why.
    </p>
    <div class="row" style="gap: 8px; flex-wrap: wrap">
      <input
        bind:value={explainInput}
        placeholder="news.example.com"
        spellcheck="false"
        style="flex: 1; min-width: 220px"
        onkeydown={(event) => event.key === 'Enter' && runExplain()}
      />
      <button onclick={runExplain} disabled={explaining || !explainInput.trim()}>
        {explaining ? 'Checking...' : 'Explain'}
      </button>
    </div>
    {#if explainError}<p class="dialog-error" style="margin: 8px 0 0">{explainError}</p>{/if}
    {#if explainResult}
      <div class="explain" aria-live="polite">
        <div class="row" style="gap: 8px; flex-wrap: wrap">
          <code>{explainResult.domain}</code>
          {#if explainResult.blocked}
            <span class="pill err">Blocked</span>
          {:else}
            <span class="pill">Not Blocked</span>
          {/if}
          <span class="muted small">
            {titleCase(explainResult.mode)} mode, block threshold {percent(explainResult.block_threshold)}
          </span>
        </div>
        <ul>
          {#each explainResult.reasons as reason, i (i)}
            <li>{reason}</li>
          {/each}
        </ul>
        <p class="muted small" style="margin: 0">
          {#if explainResult.threat}
            Threat label {titleCase(explainResult.threat.category)} at {percent(explainResult.threat.confidence)}{#if explainResult.threat.threat_score != null} (model threat score {percent(explainResult.threat.threat_score)}){:else} (not scored by the model){/if}{#if explainResult.threat.over_threshold}, at or above the threshold{:else}, below the threshold{/if}{#if explainResult.threat.severity === 'disputed'}, disputed{/if}.
            {#if explainResult.threat.evidence}
              <span class="evidence-line">Evidence: {explainResult.threat.evidence}.</span>
            {/if}
            {#if explainResult.page_reading}
              The page read as <strong>{titleCase(explainResult.page_reading.category)}</strong>
              at {percent(explainResult.page_reading.confidence)}{#if explainResult.page_reading.cues.length}
                ({explainResult.page_reading.cues.slice(0, 3).join(', ')}){/if}.
            {/if}
            {#if explainResult.page_adjustment}
              The <strong>{pageRuleLabel(explainResult.page_adjustment.rule)}</strong> page rule
              {#if explainResult.page_adjustment.confidence < explainResult.page_adjustment.prior_confidence}
                capped it from {percent(explainResult.page_adjustment.prior_confidence)}
                to {percent(explainResult.page_adjustment.confidence)}
              {:else}
                raised it from {percent(explainResult.page_adjustment.prior_confidence)}
                to {percent(explainResult.page_adjustment.confidence)}
              {/if}
              when the page behind it was read.
            {/if}
          {:else}
            No threat verdict yet.
          {/if}
          {#if explainResult.category}
            Category {titleCase(explainResult.category.category)} at {percent(explainResult.category.confidence)}.
          {/if}
          {#if explainResult.sighting}
            Looked up on {fmt(explainResult.sighting.days)} day{explainResult.sighting.days === 1 ? '' : 's'}
            by {fmt(explainResult.sighting.clients)}{explainResult.sighting.clients >= 16 ? '+' : ''} client{explainResult.sighting.clients === 1 ? '' : 's'}{#if explainResult.sighting.established}{' '}(established on this network){/if}.
          {/if}
          {#if explainResult.threat_feed}
            Listed by {explainResult.threat_feed.source} as {titleCase(explainResult.threat_feed.label)}.
          {/if}
        </p>
        {#if explainResult.signals?.length}
          <dl class="signals small">
            {#each explainResult.signals as s (s.signal)}
              <dt>
                <span class="pill tag" class:ok={s.direction === 'benign'} class:err={s.direction === 'threat'} title={s.direction}>{signalLabel(s.signal)}</span>
                {#if s.value != null}<span class="muted">{percent(s.value)}</span>{/if}
              </dt>
              <dd class="muted">{s.detail}</dd>
            {/each}
          </dl>
          <p class="muted small" style="margin: 0">
            These inputs are scored on their own. None of them decides: the
            confidence and the block threshold still do.
          </p>
        {/if}
      </div>
    {/if}
  </div>

  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Detected Threats ({fmt(total)})</h3>
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input type="search" placeholder="Search Domains" aria-label="Search domains" bind:value={search} style="min-width: 200px" />
        <select bind:value={categoryFilter} aria-label="Filter by category" style="min-width: 150px">
          <option value="">All Categories</option>
          {#each categories as category (category)}
            <option value={category}>{titleCase(category)}</option>
          {/each}
        </select>
        <select bind:value={severityFilter} aria-label="Filter by severity" style="min-width: 145px">
          {#each SEVERITY_FILTERS as f (f.label)}
            <option value={f.value}>{f.label}</option>
          {/each}
        </select>
        <select bind:value={exemptionFilter} aria-label="Filter by exemption" style="min-width: 145px">
          {#each EXEMPTION_FILTERS as f (f.label)}
            <option value={f.value}>{f.label}</option>
          {/each}
        </select>
        <button class="secondary" onclick={() => exportThreats('csv')} disabled={!!exporting}>
          {exporting === 'csv' ? 'Exporting...' : 'Export CSV'}
        </button>
        <button class="secondary" onclick={() => exportThreats('list')} disabled={!!exporting}>
          {exporting === 'list' ? 'Exporting...' : 'Domain List'}
        </button>
        <button class="secondary" title="Every exemption, mislabelled mark and relabel, for retraining a model offline" onclick={exportCorrections} disabled={!!exporting}>
          {exporting === 'corrections' ? 'Exporting...' : 'Corrections CSV'}
        </button>
        <button class="secondary" onclick={load}>Reload</button>
        <ColumnPicker table="ai-threats" columns={COLUMNS} />
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          {#if show('category')}<th>Category</th>{/if}
          {#if show('state')}<th>State</th>{/if}
          {#if show('decision')}<th title="What DNS does about the domain: block, override (your decision wins), monitor (reported, not blocking) or allow">Decision</th>{/if}
          {#if show('confidence')}<th class="num">Confidence</th>{/if}
          {#if show('score')}<th class="num" title="The model's own probability for the threat families, before evidence and the block threshold">Threat Score</th>{/if}
          {#if show('signals')}<th title="Each input scored on its own, for inspection only: none of them decides">Signals</th>{/if}
          {#if show('reason')}<th title="Why the domain was judged a threat">Why</th>{/if}
          {#if show('seen')}<th class="num" title="In how many scans the domain showed up in your DNS traffic">Seen</th>{/if}
          {#if show('evidence')}<th>Evidence</th>{/if}
          {#if show('re-check')}<th title="When the threat expires: it is checked again if the domain is still being queried, and dropped otherwise">Re-Check</th>{/if}
          {#if isAdmin}<th class="num">Actions</th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each rows as r (r.domain)}
          <tr>
            <td>
              <code>{r.domain}</code>
            </td>
            {#if show('category')}
            <td>
              {#if r.category_override}
                <span title={r.category ? `Your label; the AI detected ${titleCase(r.category)}` : 'Your label'}>{titleCase(r.category_override)}</span>
                <span class="pill ok tag" title="You labelled this domain a threat: it counts as one whatever the AI scored">Set By You</span>
                {#if r.category && r.category !== r.category_override}<div class="muted" style="font-size: 0.75rem">Detected: {titleCase(r.category)}</div>{/if}
              {:else if r.category}
                {titleCase(r.category)}
                {#if r.classification && r.classification !== r.category}
                  <div class="muted" style="font-size: 0.75rem" title="What the categorization pass called the domain; the threat score is what made it a threat">Classified: {titleCase(r.classification)}</div>
                {/if}
              {:else}<span class="muted">-</span>{/if}
            </td>
            {/if}
            {#if show('state')}
            <td>
              {#if r.not_threat}
                <span class="pill ok tag" title="You marked this domain as not a threat: the detection is kept for audit but never blocks">Mislabelled</span>
              {:else if r.severity === 'disputed'}
                <span class="pill" title="Disputed by the verifier or by this network's own evidence (see Evidence): the domain is never auto-blocked">Disputed</span>
              {:else if r.blocked}
                <span class="pill err" title="In the current block snapshot: auto-blocked in enforce mode">Auto-Blocked</span>
              {:else if r.category_blocked}
                <span class="pill err" title="A filtering group blocks this category: blocked for that group's clients, in either mode">Blocked by Category</span>
              {:else if r.overridden}
                <span class="pill ok tag" title="Exempt: the operator's allow override vetoed blocking for this domain">Exempt</span>
              {:else}
                <span class="pill" title="Not in the block snapshot: below the block threshold, not an auto-block category, or expired">Not Blocked</span>
              {/if}
            </td>
            {/if}
            {#if show('decision')}
            <td>
              {#if r.decision === 'block'}
                <span class="pill err" title="Blocked in the current AI block snapshot">Block</span>
              {:else if r.decision === 'override'}
                <span class="pill ok tag" title="Your decision wins: exempt, or marked not a threat">Override</span>
              {:else if r.decision === 'monitor'}
                <span class="pill" title="Detected and reported, but the enforcement rules do not block it">Monitor</span>
              {:else}
                <span class="pill" title="Not blocked">Allow</span>
              {/if}
            </td>
            {/if}
            {#if show('confidence')}
              <td class="num">{percent(r.confidence)}</td>
            {/if}
            {#if show('score')}
              <td class="num" title={r.threat_score == null ? 'Not scored: this backend reports no per-label probability' : 'The model\'s own threat score'}>
                {r.threat_score == null ? '—' : percent(r.threat_score)}
              </td>
            {/if}
            {#if show('signals')}
              <td class="signals-cell">
                {#each r.signals || [] as s (s.signal)}
                  <span class="pill tag" class:ok={s.direction === 'benign'} class:err={s.direction === 'threat'} title={`${signalLabel(s.signal)} (${s.direction}): ${s.detail}`}>
                    {signalLabel(s.signal)}{#if s.value != null} {percent(s.value)}{/if}
                  </span>
                {:else}
                  <span class="muted">-</span>
                {/each}
              </td>
            {/if}
            {#if show('reason')}
              <td class="muted evidence" title={r.reason}>{r.reason || '-'}</td>
            {/if}
            {#if show('seen')}<td class="num">{fmt(r.observations)}</td>{/if}
            {#if show('evidence')}
              <td class="muted evidence" title={r.evidence}>{r.evidence || '-'}</td>
            {/if}
            {#if show('re-check')}<td class="muted nowrap">{stampTime(r.expires_at, formatDate)}</td>{/if}
            {#if isAdmin}
              <td class="num">
                {#if r.not_threat}
                  <button class="secondary" style="padding: 2px 8px; font-size: 0.75rem" title="Restore: treat this detection as a threat again" onclick={() => restoreThreat(r.domain)}>Restore</button>
                {:else}
                  {#if r.overridden}
                    <IconButton icon="disallow" label="Unexempt: let the AI block this domain again" onclick={() => setExempt(r.domain, false)} />
                  {:else}
                    <IconButton icon="allow" label="Exempt: never let the AI block this domain or its subdomains" onclick={() => setExempt(r.domain, true)} />
                  {/if}
                  {#if r.category_override}
                    <IconButton icon="undo" label="Remove your label: let the AI decide again" onclick={() => clearLabel(r.domain)} />
                  {:else}
                    <IconButton icon="tag" label="Mislabelled: not a threat, record a correction that stops this detection blocking" title="Not a threat: record a correction that stops this detection blocking" onclick={() => (correctionDomain = r.domain)} />
                  {/if}
                {/if}
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
    {#if !rows.length}
      <p class="muted">
        {#if search.trim() || categoryFilter.trim() || severityFilter || exemptionFilter}
          No threats match these filters.
        {:else}
          No threats found yet. Ordinary sites never appear here.
        {/if}
      </p>
    {/if}
  </div>

  {#if total > PER_PAGE}
    <div class="row" style="margin-top: 12px">
      <button class="secondary" onclick={() => goPage(-1)} disabled={page <= 1}>← Prev</button>
      <span class="muted">Page {page} of {pages()}</span>
      <button class="secondary" onclick={() => goPage(1)} disabled={page >= pages()}>Next →</button>
    </div>
  {/if}
{/if}

{#if exemptionDomain}
  <AiExemptionDialog
    domain={exemptionDomain}
    onCancel={() => (exemptionDomain = null)}
    onConfirm={(reason) => applyExemption(exemptionDomain, true, reason)}
  />
{/if}

{#if correctionDomain}
  <AiCorrectionDialog
    domain={correctionDomain}
    categories={categories.filter((c) => !threatLabels.some((l) => l.toLowerCase() === c.toLowerCase()))}
    onCancel={() => (correctionDomain = null)}
    onConfirm={(reason, category) => applyCorrection(correctionDomain, reason, category)}
  />
{/if}

<style>
  .explain { margin-top: 12px; }
  .explain ul { margin: 8px 0; padding-left: 18px; font-size: 0.85rem; }
  .explain li { margin: 2px 0; }
  .explain .small { font-size: 0.78rem; }
  .evidence-line { display: block; margin: 2px 0; word-break: break-word; }
  .warn { color: var(--danger); font-size: 0.85rem; margin: 0 0 8px; }
  /* The label-editor and Check a Domain errors use this class too; without a
     rule here they rendered in the normal text colour, not as errors. */
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .labels { display: flex; flex-wrap: wrap; gap: 6px 18px; }
  .check { display: flex; align-items: center; gap: 6px; font-size: 0.85rem; }
  .check input { width: auto; }
  .nowrap { white-space: nowrap; }
  .tag { margin-left: 6px; }
  .signals-cell { max-width: 240px; }
  .signals-cell .tag { margin: 1px 3px 1px 0; }
  .evidence { max-width: 200px; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>

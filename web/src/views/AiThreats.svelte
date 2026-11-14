<script>
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDate } from '../datetime.svelte.js';
  import { backendLabel, percent, titleCase } from '../aiLabels.js';

  const PAGE_RULE_LABELS = {
    evidence: 'Evidence only',
    corroborate: 'Corroborate',
    decide: 'Decide',
  };
  function pageRuleLabel(rule) {
    return PAGE_RULE_LABELS[rule] || rule;
  }
  import ColumnPicker from '../ColumnPicker.svelte';
  import { isHidden } from '../columns.svelte.js';
  import AiExemptionDialog from './AiExemptionDialog.svelte';
  import AiCorrectionDialog from './AiCorrectionDialog.svelte';

  const COLUMNS = [
    { key: 'domain', label: 'Domain', locked: true },
    { key: 'category', label: 'Category' },
    { key: 'state', label: 'State' },
    { key: 'confidence', label: 'Confidence' },
    { key: 'seen', label: 'Seen' },
    { key: 'evidence', label: 'Evidence' },
    { key: 're-check', label: 'Re-Check' },
  ];
  const show = (key) => !isHidden('ai-threats', key);

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
  // The threat channel's own model, when it has one, against the shared one.
  let threatModelPath = $state('');
  let sharedModelPath = $state('');
  let modelDedicated = $state(false);
  let threatBackendName = $state('');
  let savingModel = $state(false);
  let modelNotice = $state(null);
  let modelError = $state(null);
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

  async function loadCategories() {
    try {
      const status = await api.aiStatus();
      modelLabels = [...new Set(status?.backend_categories || [])].sort();
      threatLabels = [...(status?.auto_block_categories || [])];
      labelsText = threatLabels.join(', ');
      categories = modelLabels;
      threatModelPath = status?.threat_model_path || '';
      sharedModelPath = status?.model_path || '';
      modelDedicated = !!status?.threat_model_dedicated;
      threatBackendName = status?.threat_backend || status?.backend || '';
    } catch {
      modelLabels = [];
      categories = [];
      // 404: the scanner is off. The saved list still lives in the config.
      try {
        const config = await api.config();
        threatLabels = [...(config?.ai?.auto_block_categories || [])];
        labelsText = threatLabels.join(', ');
        threatModelPath = config?.ai?.threat_model_path || '';
        sharedModelPath = config?.ai?.model_path || '';
        modelDedicated =
          !!threatModelPath.trim() && threatModelPath.trim() !== sharedModelPath.trim();
      } catch {
        threatLabels = [];
      }
    }
  }

  // The model's labels plus any already chosen that it no longer lists, so a
  // label set under another model can still be seen and unticked.
  const labelChoices = $derived([...new Set([...modelLabels, ...threatLabels])].sort());

  function toggleThreatLabel(label) {
    threatLabels = threatLabels.includes(label)
      ? threatLabels.filter((l) => l !== label)
      : [...threatLabels, label];
  }

  async function saveThreatModel() {
    savingModel = true;
    modelNotice = null;
    modelError = null;
    try {
      const path = threatModelPath.trim();
      await api.updateSettings({ ai: { threat_model_path: path } });
      modelDedicated = !!path && path !== sharedModelPath.trim();
      modelNotice = path
        ? 'Threat model saved. It is loaded at the next restart.'
        : 'Threat model cleared: the threat channel goes back to the shared model at the next restart.';
      await loadCategories();
    } catch (e) {
      modelError = formatApiError(e);
    } finally {
      savingModel = false;
    }
  }

  async function saveThreatLabels(list = threatLabels) {
    savingLabels = true;
    labelsNotice = null;
    labelsError = null;
    try {
      await api.updateSettings({ ai: { auto_block_categories: [...list] } });
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
        : `${domain} is no longer exempt; blocking applies again once a fresh threat qualifies.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function exportThreats(format) {
    exporting = format;
    error = null;
    notice = null;
    try {
      const text = await api.aiThreatsExport(format);
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = format === 'list' ? 'ai-threats.txt' : 'ai-threats.csv';
      a.click();
      URL.revokeObjectURL(url);
      notice = `Exported ${format === 'list' ? 'the plain domain list' : 'the CSV'} of active threats.`;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      exporting = '';
    }
  }

  async function exportCorrections() {
    notice = null;
    error = null;
    try {
      const text = await api.aiCorrections('csv');
      const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ai-corrections.csv';
      a.click();
      URL.revokeObjectURL(url);
      notice = 'Exported every exemption, mislabelled mark and relabel as training data.';
    } catch (e) {
      error = formatApiError(e);
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
      notice = `${domain} is marked not a threat${category ? ` and relabelled as '${titleCase(category)}'` : ''}. It no longer blocks or appears in the exported list; the detection stays visible until you restore it.`;
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

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  // Unset times come back as the UNIX epoch.
  function stamp(value, format) {
    if (!value) return '-';
    const ms = Date.parse(value);
    return Number.isNaN(ms) || ms <= 0 ? '-' : format(ms);
  }

  // Reload on mount and whenever the search box changes (back to page 1,
  // since the filter changed the list). Typing waits for a pause.
  let searchTimer;
  let firstLoad = true;
  loadCategories();

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
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if !loading}
  <div class="card" style="margin-bottom: 14px">
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Threat Model</h3>
      {#if isAdmin}
        <button onclick={saveThreatModel} disabled={savingModel}>
          {savingModel ? 'Saving...' : 'Save Model'}
        </button>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 10px">
      Leave the path empty to use the shared classifier, where the labels
      below define what counts as a threat. Name a model here and the threat
      channel detects on its own: every label it reports is a threat and blocks
      in Enforce mode at or above the block threshold. A model change is loaded
      at the next restart.
    </p>
    <div class="grid2">
      <label>
        Threat Model Path
        <input bind:value={threatModelPath} placeholder="Empty: use the shared model" spellcheck="false" disabled={!isAdmin} />
      </label>
      <label>
        Threat Channel
        <span class="muted">
          {backendLabel(threatBackendName)}
          <span class="pill">{modelDedicated ? 'Own Model' : 'Shared Model'}</span>
        </span>
      </label>
      <label>
        Shared Model
        <span class="muted"><code>{sharedModelPath || 'Built-in heuristic rules'}</code></span>
      </label>
    </div>
    {#if modelNotice}<p class="muted" style="color: var(--ok); margin: 8px 0 0">{modelNotice}</p>{/if}
    {#if modelError}<p class="dialog-error" style="margin: 8px 0 0">{modelError}</p>{/if}
  </div>
{/if}

{#if loading}
  <div class="card">
    <p class="muted">Loading...</p>
  </div>
{:else if disabled}
  <div class="card">
    <h3 style="margin: 0 0 10px">AI Scanner Is Off</h3>
    <p class="muted" style="margin: 0">
      There are no threats. Turn the scanner on in Settings → AI Scanner; it
      starts after the next restart.
    </p>
  </div>
{:else}
  <div class="card" style="margin-bottom: 14px">
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Labels Treated as Threats</h3>
      {#if isAdmin && !modelDedicated}
        <button onclick={saveThreatLabels} disabled={savingLabels}>
          {savingLabels ? 'Saving...' : 'Save Labels'}
        </button>
      {/if}
    </div>
    {#if modelDedicated}
      <p class="muted help" style="margin: 0 0 10px">
        A dedicated threat model is in use, so it decides what a threat is:
        every label it reports blocks in Enforce mode once its confidence
        reaches the block threshold and the verifier does not dispute it. The
        list below only applies when the threat channel goes back to the shared
        model.
      </p>
    {:else}
      <p class="muted help" style="margin: 0 0 10px">
        The threat channel reports a domain only when its label is ticked here.
        In Enforce mode a reported threat is auto-blocked when its confidence is
        at or above the block threshold and the verifier does not dispute it; a
        label that is not ticked never blocks. Name a threat model above to let
        that model decide instead.
      </p>
    {/if}
    {#if labelsNotice}<p class="muted" style="color: var(--ok); margin: 0 0 8px">{labelsNotice}</p>{/if}
    {#if labelsError}<p class="dialog-error">{labelsError}</p>{/if}
    {#if labelChoices.length}
      <div class="labels">
        {#each labelChoices as label (label)}
          <label class="check">
            <input
              type="checkbox"
              checked={threatLabels.includes(label)}
              onchange={() => toggleThreatLabel(label)}
              disabled={!isAdmin || modelDedicated}
            />
            <span>{titleCase(label)}{#if !modelLabels.includes(label)}<span class="muted"> (not in the loaded model)</span>{/if}</span>
          </label>
        {/each}
      </div>
    {:else}
      <p class="muted" style="margin: 0">No labels to choose from: the scanner has no model loaded.</p>
    {/if}
  </div>

  {#if isAdmin && disabled && !modelLabels.length}
    <div class="card" style="margin-bottom: 14px">
      <h3 style="margin: 0 0 8px">Labels Treated as Threats</h3>
      <p class="muted help" style="margin: 0 0 8px">
        No model is loaded, so there are no labels to tick. Type the labels
        the threat channel should report, separated by commas; they take
        effect when the scanner has a model again.
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

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 8px">Check a Domain</h3>
    <p class="muted help" style="margin: 0 0 10px">
      Why is this domain blocked - or not? Both channels' verdicts, your
      overrides, and which filtering groups block its category.
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
      <div class="explain">
        <div class="row" style="gap: 8px; flex-wrap: wrap">
          <code>{explainResult.domain}</code>
          {#if explainResult.blocked}
            <span class="pill err">Blocked</span>
          {:else}
            <span class="pill">Not Blocked</span>
          {/if}
          <span class="muted small">
            {explainResult.mode} mode, block threshold {percent(explainResult.block_threshold)}{#if explainResult.threat_model_dedicated}, own threat model{/if}
          </span>
        </div>
        <ul>
          {#each explainResult.reasons as reason (reason)}
            <li>{reason}</li>
          {/each}
        </ul>
        <p class="muted small" style="margin: 0">
          {#if explainResult.threat}
            Threat label {titleCase(explainResult.threat.category)} at {percent(explainResult.threat.confidence)}{#if explainResult.threat.over_threshold}, at or above the threshold{:else}, below the threshold{/if}{#if explainResult.threat.severity === 'disputed'}, disputed by the verifier{/if}.
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
        </p>
      </div>
    {/if}
  </div>

  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Detected Threats ({fmt(total)})</h3>
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input type="search" placeholder="Search Domains" bind:value={search} style="min-width: 200px" />
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
        <button class="secondary" title="Every exemption, mislabelled mark and relabel, for retraining a model offline" onclick={exportCorrections}>
          Corrections CSV
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
          {#if show('confidence')}<th class="num">Confidence</th>{/if}
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
            <td>{#if r.category}{titleCase(r.category)}{:else}<span class="muted">-</span>{/if}</td>
            {/if}
            {#if show('state')}
            <td>
              {#if r.not_threat}
                <span class="pill ok tag" title="You marked this domain as not a threat: the detection is kept for audit but never blocks">Mislabelled</span>
              {:else if r.severity === 'disputed'}
                <span class="pill" title="The verifier disagreed with this threat detection: the domain is never auto-blocked">Disputed</span>
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
            {#if show('confidence')}
              <td class="num">{percent(r.confidence)}</td>
            {/if}
            {#if show('seen')}<td class="num">{fmt(r.observations)}</td>{/if}
            {#if show('evidence')}
              <td class="muted evidence" title={r.evidence}>{r.evidence || '-'}</td>
            {/if}
            {#if show('re-check')}<td class="muted nowrap">{stamp(r.expires_at, formatDate)}</td>{/if}
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
                  <button class="secondary" style="padding: 2px 8px; font-size: 0.75rem" title="Not a threat: record a correction that stops this detection blocking" onclick={() => (correctionDomain = r.domain)}>Mislabelled</button>
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
          No threats yet - benign lookups never appear here; entries
          show up when the scanner classifies a domain badly enough to matter.
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
    categories={categories}
    onCancel={() => (correctionDomain = null)}
    onConfirm={(reason, category) => applyCorrection(correctionDomain, reason, category)}
  />
{/if}

<style>
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .grid2 label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
  .explain { margin-top: 12px; }
  .explain ul { margin: 8px 0; padding-left: 18px; font-size: 0.85rem; }
  .explain li { margin: 2px 0; }
  .explain .small { font-size: 0.78rem; }
  .labels { display: flex; flex-wrap: wrap; gap: 6px 18px; }
  .check { display: flex; align-items: center; gap: 6px; font-size: 0.85rem; }
  .check input { width: auto; }
  .nowrap { white-space: nowrap; }
  .evidence { max-width: 200px; font-size: 0.78rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
  }
</style>

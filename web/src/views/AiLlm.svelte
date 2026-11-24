<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { titleCase } from '../aiLabels.js';

  // The language-model reader (a local Ollama server): connection, models
  // and the Ollama server itself.
  let llm = $state(null);
  let error = $state(null);
  let notice = $state(null);
  let busy = $state(false);
  let testing = $state(false);
  let testResult = $state(null);
  let form = $state(null);
  let downloadName = $state('');
  let pollTimer = null;
  let destroyed = false;

  const isAdmin = getStoredUser()?.role !== 'viewer';
  // Must match UpdateState::is_running on the server.
  const RUNNING = ['preparing', 'downloading', 'cloning', 'building', 'installing', 'applying', 'restarting', 'rolling_back'];

  const pulling = $derived(!!llm?.pull && !llm.pull.done);
  const testRunning = $derived(!!llm?.test?.running);
  const operation = $derived(llm?.service?.operation || null);
  // The shared update state also reports server updates: only show it here
  // when it is about Ollama.
  const ollamaOp = $derived(
    operation && /ollama/i.test(operation.message || '') ? operation : null,
  );
  const serviceRunning = $derived(!!ollamaOp && RUNNING.includes(ollamaOp.phase));
  const otherUpdateRunning = $derived(
    !!operation && RUNNING.includes(operation.phase) && !ollamaOp,
  );

  function fmtSize(bytes) {
    if (!bytes) return '-';
    if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
    if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(0)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
  }

  function fill(data) {
    form = {
      enabled: !!data.enabled,
      url: data.url,
      model: data.model,
      perScan: data.candidates_per_scan,
      timeout: data.timeout_secs,
    };
  }

  async function load(keepForm = false) {
    try {
      const data = await api.aiLlm();
      llm = data;
      if (!keepForm || !form) fill(data);
      error = null;
    } catch (e) {
      error = formatApiError(e);
    }
    schedule();
  }

  function schedule() {
    clearTimeout(pollTimer);
    if (destroyed) return;
    if (pulling || serviceRunning || testRunning) {
      pollTimer = setTimeout(() => load(true), 2000);
    }
  }

  async function save(extra = {}) {
    busy = true;
    notice = null;
    error = null;
    try {
      await api.updateSettings({
        ai: {
          llm_enabled: form.enabled,
          llm_url: form.url.trim(),
          llm_model: form.model.trim(),
          llm_candidates_per_scan: Number(form.perScan),
          llm_timeout_secs: Number(form.timeout),
          ...extra,
        },
      });
      notice = 'Language model settings saved.';
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  // The question runs on the server; the page checks back for the answer.
  async function test() {
    testing = true;
    testResult = null;
    try {
      await api.aiLlmTest({ url: form.url.trim(), model: form.model.trim() });
      await load(true);
    } catch (e) {
      testResult = { ok: false, error: formatApiError(e) };
    } finally {
      testing = false;
    }
  }
  const shownTest = $derived(testResult || (llm?.test && !llm.test.running ? llm.test : null));

  async function pull(model) {
    const name = (model || '').trim();
    if (!name) return;
    notice = null;
    error = null;
    try {
      await api.aiLlmPull(name);
      notice = `Downloading ${name}...`;
      downloadName = '';
      await load(true);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function remove(model) {
    if (!confirm(`Delete the model ${model} from the Ollama server?`)) return;
    notice = null;
    error = null;
    try {
      await api.aiLlmDelete(model);
      notice = `Deleted ${model}.`;
      await load(true);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  async function useModel(model) {
    form.model = model;
    await save({ llm_model: model });
  }

  const SERVICE_CONFIRM = {
    install:
      'Install Ollama on this server? It downloads several hundred MB plus about 1 GB for the recommended model, and needs about 3.5 GB of memory in total. It runs at low priority and only listens on this machine.',
    update: 'Update Ollama to the newest version? Your models are kept.',
    remove: 'Remove Ollama and every model it downloaded from this server?',
  };

  async function service(action) {
    if (!confirm(SERVICE_CONFIRM[action])) return;
    notice = null;
    error = null;
    try {
      await api.aiLlmService(action);
      await load(true);
    } catch (e) {
      error = formatApiError(e);
    }
  }

  onDestroy(() => {
    destroyed = true;
    clearTimeout(pollTimer);
  });

  $effect(() => {
    load();
  });
</script>

{#if error && !llm}
  <div class="card"><p style="color: var(--danger); margin: 0">{error}</p></div>
{:else if !llm || !form}
  <div class="card"><p class="muted" style="margin: 0">Loading...</p></div>
{:else}
  {#if notice}<div class="card notice">{notice}</div>{/if}
  {#if error}<div class="card" style="color: var(--danger)">{error}</div>{/if}

  <div class="card">
    <div class="spread" style="margin-bottom: 8px; gap: 10px; flex-wrap: wrap">
      <h3 style="margin: 0">Language Model Reader</h3>
      {#if llm.reachable}
        <span class="pill ok">Connected to Ollama {llm.version}</span>
      {:else}
        <span class="pill bad">Ollama not reachable</span>
      {/if}
    </div>
    <p class="muted help" style="margin: 0 0 6px">
      A local language model reads the pages the AI has already fetched, for
      the domains it is least sure of: it can confirm a suspected threat or
      name an unsure domain's category. It never clears a threat, and its
      labels are never used for training.
    </p>
    <details class="how" style="margin: 0 0 10px">
      <summary class="muted">How it works</summary>
      <ul class="how-list muted">
        <li>Only pages already read by the page reader are used: the model never
          contacts a site. Turn on Read Pages on the Scanner tab.</li>
        <li>A threat below the block threshold that the model also reads as a
          threat is raised, to blocking when both are confident (not with the
          Evidence-only reading rule).</li>
        <li>A domain categorized below 50% takes the category the model names,
          when the model is surer than the name was.</li>
        <li>Each answer takes seconds on a CPU, so only a few pages are read
          per scan, threats first.</li>
        <li>The page is written by the site, so the model is told to ignore
          instructions in it, and it can only strengthen a threat.</li>
      </ul>
    </details>
    {#if !llm.reachable && llm.error}
      <p class="muted small" style="overflow-wrap: anywhere">{llm.error}</p>
    {/if}
    <div class="form-grid">
      <label class="check">
        <input type="checkbox" bind:checked={form.enabled} disabled={!isAdmin} />
        <span>Use the Language Model</span>
      </label>
      <label><span>Ollama Address</span><input bind:value={form.url} disabled={!isAdmin} placeholder="http://127.0.0.1:11434" /></label>
      <label>
        <span>Model</span>
        <input bind:value={form.model} list="llm-installed" disabled={!isAdmin} placeholder="qwen2.5:1.5b" />
        <datalist id="llm-installed">
          {#each llm.models || [] as m (m.name)}<option value={m.name}></option>{/each}
        </datalist>
      </label>
      <label><span>Pages Per Scan</span><input type="number" min="1" max="32" bind:value={form.perScan} disabled={!isAdmin} /></label>
      <label><span>Answer Time Limit (Seconds)</span><input type="number" min="5" max="600" bind:value={form.timeout} disabled={!isAdmin} /></label>
    </div>
    {#if llm.reachable && !llm.model_present}
      <p class="small" style="color: var(--warn)">
        The model {llm.model} is not on this Ollama server yet. Download it below.
      </p>
    {/if}
    {#if isAdmin}
      <div class="row" style="margin-top: 10px; gap: 10px; flex-wrap: wrap">
        <button onclick={() => save()} disabled={busy}>{busy ? 'Saving...' : 'Save'}</button>
        <button class="secondary" onclick={test} disabled={testing || testRunning}>{testing || testRunning ? 'Asking the model (the first answer can take a few minutes)...' : 'Test'}</button>
      </div>
    {/if}
    {#if shownTest}
      <p class="small" style="margin: 10px 0 0">
        {#if shownTest.ok}
          {shownTest.model ? `${shownTest.model} answered` : 'Answered'} in {(shownTest.seconds || 0).toFixed(1)}s: a sample careers page reads as
          <strong>{shownTest.category ? titleCase(shownTest.category) : 'no listed category'}</strong>
          ({Math.round(shownTest.confidence * 100)}%){shownTest.reason ? `, "${shownTest.reason}"` : ''}.
          {#if shownTest.seconds > 30}<span class="muted"> That is slow: a smaller model will read more pages per scan.</span>{/if}
        {:else}
          <span style="color: var(--danger)">Test failed: {shownTest.error}</span>
        {/if}
      </p>
    {/if}
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">Models</h3>
    {#if !llm.reachable}
      <p class="muted" style="margin: 0">Connect to an Ollama server to manage its models.</p>
    {:else}
      {#if llm.models?.length}
        <table>
          <thead>
            <tr><th>Model</th><th>Size</th><th>Details</th><th>Updated</th><th></th></tr>
          </thead>
          <tbody>
            {#each llm.models as m (m.name)}
              <tr>
                <td>
                  <code>{m.name}</code>
                  {#if m.name === llm.model}<span class="pill ok">In Use</span>{/if}
                </td>
                <td>{fmtSize(m.size)}</td>
                <td class="muted">{[m.parameter_size, m.quantization].filter(Boolean).join(', ') || '-'}</td>
                <td class="muted">{m.modified_at ? formatDateTime(m.modified_at) : '-'}</td>
                <td class="actions">
                  {#if isAdmin}
                    {#if m.name !== llm.model}
                      <button class="secondary small-btn" onclick={() => useModel(m.name)} disabled={busy}>Use</button>
                    {/if}
                    <button class="secondary small-btn" onclick={() => pull(m.name)} disabled={pulling} title="Download what changed since this model was fetched">Update</button>
                    <button class="secondary small-btn" onclick={() => remove(m.name)} disabled={pulling}>Delete</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted" style="margin: 0 0 10px">No models downloaded yet.</p>
      {/if}

      {#if llm.pull}
        <div style="margin-top: 12px">
          {#if !llm.pull.done}
            <div class="small">Downloading <code>{llm.pull.model}</code>: {llm.pull.status}</div>
            {#if llm.pull.total}
              <progress max={llm.pull.total} value={llm.pull.completed}></progress>
              <span class="muted small">{fmtSize(llm.pull.completed)} of {fmtSize(llm.pull.total)}</span>
            {/if}
          {:else if llm.pull.error}
            <div class="small" style="color: var(--danger)">Download of {llm.pull.model} failed: {llm.pull.error}</div>
          {:else}
            <div class="small">Downloaded {llm.pull.model}.</div>
          {/if}
        </div>
      {/if}

      {#if isAdmin}
        <div class="row" style="margin-top: 12px; gap: 10px; flex-wrap: wrap; align-items: flex-end">
          <label style="flex: 1; min-width: 220px">
            <span class="small">Download a Model</span>
            <input bind:value={downloadName} list="llm-suggested" placeholder="qwen2.5:1.5b" />
            <datalist id="llm-suggested">
              {#each llm.suggested_models || [] as s (s.name)}<option value={s.name}>{s.note}</option>{/each}
            </datalist>
          </label>
          <button onclick={() => pull(downloadName)} disabled={pulling || !downloadName.trim()}>Download</button>
        </div>
        <details class="how" style="margin-top: 8px">
          <summary class="muted">Which model?</summary>
          <ul class="how-list muted">
            {#each llm.suggested_models || [] as s (s.name)}
              <li><code>{s.name}</code>: {s.note}</li>
            {/each}
            <li>Any model from the Ollama library works; smaller ones answer faster on a CPU.</li>
          </ul>
        </details>
      {/if}
    {/if}
  </div>

  <div class="card" style="margin-top: 14px">
    <h3 style="margin: 0 0 10px">Ollama Server</h3>
    <table>
      <tbody>
        <tr>
          <td>Installed Version</td>
          <td>{llm.version || (llm.service.installed ? 'Installed, not answering' : 'Not installed')}</td>
        </tr>
        <tr>
          <td>Newest Version</td>
          <td>
            {llm.latest_version || 'Unknown'}
            {#if llm.update_available}<span class="pill warn-pill">Update Available</span>{/if}
          </td>
        </tr>
      </tbody>
    </table>
    {#if ollamaOp}
      <div style="margin-top: 10px">
        <span class="pill">{titleCase(ollamaOp.phase)}</span>
        <span class="muted">{ollamaOp.message}</span>
      </div>
    {/if}
    {#if !llm.service.local}
      <p class="muted small" style="margin: 10px 0 0">
        This Ollama runs on another machine. Install, update and remove it there.
      </p>
    {:else if !llm.service.manageable}
      <p class="muted small" style="margin: 10px 0 0">
        This server cannot install software from the console (no update
        service). Install Ollama by re-running the Daygle DNS installer with
        <code>DAYGLE_DNS_OLLAMA=1</code>, or with Ollama's own installer.
      </p>
    {:else if isAdmin}
      <div class="row" style="margin-top: 12px; gap: 10px; flex-wrap: wrap">
        {#if !llm.service.installed && !llm.reachable}
          <button onclick={() => service('install')} disabled={serviceRunning || otherUpdateRunning}>Install Ollama</button>
        {:else}
          <button onclick={() => service('update')} disabled={serviceRunning || otherUpdateRunning}>
            {llm.update_available ? `Update to ${llm.latest_version}` : 'Reinstall / Update'}
          </button>
          <button class="secondary" onclick={() => service('remove')} disabled={serviceRunning || otherUpdateRunning}>Remove Ollama</button>
        {/if}
        {#if otherUpdateRunning}<span class="muted small">A server update is running; wait for it to finish.</span>{/if}
      </div>
      <p class="muted small" style="margin: 8px 0 0">
        Installed with Ollama's official installer through the server's update
        service. Ollama listens only on this machine and runs below the DNS
        server's priority.
      </p>
    {/if}
  </div>
{/if}

<style>
  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 12px;
    align-items: end;
  }
  label:not(.check) { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  label.check { display: flex; flex-direction: row; align-items: center; gap: 8px; padding-bottom: 8px; }
  label.check span { color: var(--text); }
  .small { font-size: 0.85rem; }
  .how summary { cursor: pointer; font-size: 0.85rem; }
  .how-list { margin: 6px 0 0; padding-left: 18px; font-size: 0.85rem; line-height: 1.45; }
  .how-list li { margin: 3px 0; }
  .actions { white-space: nowrap; text-align: right; }
  .small-btn { padding: 2px 8px; margin-left: 4px; }
  .pill.ok { color: var(--ok, inherit); }
  .pill.bad { color: var(--danger); }
  .warn-pill { margin-left: 6px; color: var(--warn); }
  progress { width: 100%; max-width: 420px; height: 10px; vertical-align: middle; }
  .notice { margin-bottom: 14px; color: var(--ok); }
</style>

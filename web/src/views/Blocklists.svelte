<script>
  import { api, formatApiError } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';

  let sources = $state([]);
  let total = $state(0);
  let configured = $state(false); // false when the server has no sources configured
  let loading = $state(true);
  let refreshing = $state(false);
  let saving = $state(false);
  let error = $state(null);
  let notice = $state(null);

  // The in-progress source editor, or null when closed.
  let draft = $state(null);

  const FORMAT_OPTIONS = [
    { value: 'auto', label: 'Auto-Detect' },
    { value: 'domains', label: 'Domains (One per Line)' },
    { value: 'wildcard', label: 'Domains With Subdomains (e.g. oisd domainswild2)' },
    { value: 'hosts', label: 'Hosts File (e.g. StevenBlack)' },
    { value: 'adblock', label: 'Adblock (AdGuard / uBlock)' },
    { value: 'rpz', label: 'Response Policy Zone (RPZ)' },
  ];
  const FORMAT_NAMES = { domains: 'Domains', wildcard: 'Domains + Subdomains', hosts: 'Hosts File', adblock: 'Adblock', rpz: 'RPZ', auto: 'Auto-Detect' };
  const REFRESH_OPTIONS = [
    { hours: 1, label: '1 Hour' },
    { hours: 6, label: '6 Hours' },
    { hours: 12, label: '12 Hours' },
    { hours: 24, label: '24 Hours' },
    { hours: 72, label: '3 Days' },
    { hours: 168, label: '7 Days' },
  ];

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
      error = e.status === 404 ? null : formatApiError(e);
    } finally {
      loading = false;
    }
  }

  async function refreshNow() {
    refreshing = true;
    notice = null;
    try {
      const data = await api.refreshBlocklistSources();
      notice = `Refreshed - ${fmt(data.total_domains ?? 0)} domains from remote sources.`;
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      refreshing = false;
    }
  }

  function openAdd() {
    error = null;
    draft = {
      originalName: '',
      name: '',
      url: '',
      format: 'auto',
      refreshHours: 24,
      enabled: true,
      scope: 'everyone',
      result: null,
    };
  }

  function openEdit(source) {
    error = null;
    draft = {
      originalName: source.name,
      name: source.name,
      url: source.url,
      format: source.format,
      refreshHours: Math.max(1, Math.round(source.refresh_secs / 3600)),
      enabled: source.enabled,
      // DoT-only scope is retained for existing sources but is no longer
      // offered for new edits. Require an explicit replacement to avoid
      // silently broadening or narrowing a legacy source when it is saved.
      scope: source.scope === 'dot' ? '' : source.scope || 'everyone',
      result: null,
    };
  }

  function closeEditor() {
    if (saving) return;
    draft = null;
    error = null;
  }

  // 24 -> "24 Hours", 72 -> "3 Days".
  function interval(secs) {
    const hours = Math.round(secs / 3600);
    const preset = REFRESH_OPTIONS.find((o) => o.hours === hours);
    if (preset) return preset.label;
    return hours % 24 === 0 ? `${hours / 24} Days` : `${hours} Hours`;
  }

  // Only the config fields belong in the payload; the GET response also
  // carries runtime status (domains, last_fetch, last_error).
  function toConfig(source) {
    return {
      name: source.name,
      url: source.url,
      format: source.format,
      refresh_secs: source.refresh_secs,
      enabled: source.enabled,
      scope: source.scope || 'everyone',
    };
  }

  // Probe the URL live: catches a typo'd or mislabeled source before it is
  // saved, and resolves the format when the editor is set to auto-detect.
  async function validateDraft() {
    if (!draft) return null;
    draft.result = null;
    if (!draft.url.trim()) {
      draft.result = { ok: false, msg: 'Enter a URL first.' };
      return null;
    }
    const url = draft.url.trim();
    try {
      const res = await api.validateBlocklistSource(url, draft.format);
      if (res.ok) {
        const sample =
          res.sample && res.sample.length
            ? ` (e.g. ${res.sample.slice(0, 3).join(', ')})`
            : '';
        const autodetected = draft.format === 'auto' && res.format !== 'auto';
        if (autodetected) draft.format = res.format;
        draft.result = {
          ok: true,
          msg: `${fmt(res.domains)} domains as a ${res.format} list${sample}.${
            autodetected ? ` Format set to ${res.format}.` : ''
          }`,
        };
      } else {
        draft.result = { ok: false, msg: res.reason || 'content did not validate.' };
      }
      return res;
    } catch (e) {
      // Unreachable / transport error - reported but not fatal for saving
      // with an explicit format: the source will show its fetch error in the
      // table and retry on schedule.
      draft.result = {
        ok: false,
        msg: String(e.message || e),
        transport: true,
      };
      return null;
    }
  }

  async function saveSource() {
    if (!draft) return;
    const name = draft.name.trim();
    const url = draft.url.trim();
    if (!name) {
      draft.result = { ok: false, msg: 'Give the source a name.' };
      return;
    }
    if (!url) {
      draft.result = { ok: false, msg: 'Enter the blocklist URL.' };
      return;
    }
    if (!draft.scope) {
      draft.result = { ok: false, msg: 'Choose Everyone or Selected Client Groups for this source.' };
      return;
    }
    saving = true;
    error = null;
    notice = null;
    try {
      let format = draft.format;
      const verdict = await validateDraft();
      if (verdict === false || (verdict && !verdict.ok)) {
        return; // mismatch is shown on the editor; nothing was saved
      }
      if (verdict && verdict.ok) format = verdict.format;
      if (format === 'auto') {
        // Auto-detect needs a reachable URL; without one we cannot pick a
        // concrete format to store.
        draft.result = {
          ok: false,
          msg: `Could not auto-detect the format (${draft.result?.msg || 'URL unreachable'}). Pick a format manually or fix the URL.`,
        };
        return;
      }
      if (draft.format === 'auto' && format !== 'auto') draft.format = format;

      const next = sources
        .filter((s) => s.name !== draft.originalName)
        .map(toConfig);
      const duplicate = next.some(
        (s) => s.name.toLowerCase() === name.toLowerCase()
      );
      if (duplicate) {
        draft.result = { ok: false, msg: `A source named "${name}" already exists.` };
        return;
      }
      next.push({
        name,
        url,
        format,
        refresh_secs: Number(draft.refreshHours) * 3600,
        enabled: draft.enabled,
        scope: draft.scope,
      });

      // Client groups that select a renamed source follow the rename.
      const renamed = draft.originalName && draft.originalName !== name;
      await api.replaceBlocklistSources(next, renamed ? { [draft.originalName]: name } : {});
      draft = null;
      await load();
      notice = `Source "${name}" saved - fetching it now.`;
      // The save triggers a background fetch; poll until the source's last fetch time updates
      // or a short timeout passes.
      await waitForSourceUpdate(name);
    } catch (e) {
      error = formatApiError(e);
    } finally {
      saving = false;
    }
  }

  // Poll the source status until `name` has been fetched or failed (last_fetch
  // or last_error is set) or the attempts run out. Bounded so a slow feed never hangs the UI.
  async function waitForSourceUpdate(name, attempts = 10, delayMs = 1500) {
    for (let i = 0; i < attempts; i++) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      const data = await api.blocklistSources();
      sources = data.sources || [];
      total = data.total_domains || 0;
      const source = sources.find((s) => s.name === name);
      if (source && (source.last_fetch != null || source.last_error)) return;
    }
  }

  async function removeSource(source) {
    const groupsNote = source.scope === 'groups' ? ' It is also removed from the client groups that use it.' : '';
    if (!confirm(`Delete blocklist source "${source.name}"? Its domains stop being blocked.${groupsNote}`)) return;
    error = null;
    notice = null;
    try {
      const next = sources
        .filter((s) => s.name !== source.name)
        .map(toConfig);
      await api.replaceBlocklistSources(next);
      await load();
      notice = `Source "${source.name}" removed.`;
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function ago(secs) {
    if (secs === null || secs === undefined) return 'Never';
    if (secs < 60) return 'Just Now';
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  $effect(() => {
    load();
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
{:else if !configured}
  <div class="card">
    <h3 style="margin: 0 0 10px">No Blocklists Yet</h3>
    <p class="muted" style="max-width: 70ch">
      Add a published blocklist (ads, trackers, malware...) by its URL. Leave
      the format on <strong>Auto-Detect</strong> and the server works it out
      from the list itself before saving.
    </p>
    <div class="row">
      <button onclick={openAdd}>Add Blocklist</button>
    </div>
  </div>
{:else}
  <div class="card">
    <div class="spread" style="margin-bottom: 10px; gap: 10px; flex-wrap: wrap">
      <div>
        <h3 style="margin: 0">Blocklists ({sources.length})</h3>
        <span class="muted small">{fmt(total)} domains blocked for everyone</span>
      </div>
      <div class="row" style="gap: 8px">
        <button class="secondary" onclick={load}>Reload</button>
        <button class="secondary" onclick={refreshNow} disabled={refreshing}>
          {refreshing ? 'Refreshing...' : 'Refresh All'}
        </button>
        <button onclick={openAdd}>Add Blocklist</button>
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Source</th>
          <th>Format</th>
          <th>Applies To</th>
          <th>Refreshes Every</th>
          <th class="num">Domains</th>
          <th>Last Updated</th>
          <th>Status</th>
          <th class="num">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each sources as s (s.url)}
          <tr class:disabled={!s.enabled}>
            <td>
              <strong>{s.name}</strong>
              <div class="muted url" title={s.url}>{s.url}</div>
              {#if s.last_error}
                <div class="fetch-error">{s.last_error}</div>
              {/if}
            </td>
            <td>
              {#if s.format === 'wildcard'}
                <div class="pill-row">
                  <span class="pill">Domains</span>
                  <span class="pill">Subdomains</span>
                </div>
              {:else}
                <span class="pill">{FORMAT_NAMES[s.format] || s.format}</span>
              {/if}
            </td>
            <td>{s.scope === 'groups' ? 'Client Groups' : s.scope === 'dot' ? 'DoT Only (legacy)' : 'Everyone'}</td>
            <td class="muted">{interval(s.refresh_secs)}</td>
            <td class="num">{fmt(s.domains)}</td>
            <td class="muted" style="white-space: nowrap" title={ago(s.last_fetch)}>
              {s.last_fetch_at ? formatDateTime(s.last_fetch_at) : 'Never'}
            </td>
            <td>
              {#if s.last_error}
                <span class="pill err">Fetch Failed</span>
              {:else if !s.enabled}
                <span class="pill">Disabled</span>
              {:else}
                <span class="pill ok">OK</span>
              {/if}
            </td>
            <td class="num">
              <div class="row" style="gap: 6px; justify-content: flex-end">
                <button class="secondary" onclick={() => openEdit(s)}>Edit</button>
                <button class="danger" onclick={() => removeSource(s)} aria-label="Delete {s.name}">✕</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
    <p class="muted help">
      Refresh All fetches every source immediately. Sources also refresh
      automatically on their configured interval; a failed fetch is reported
      here and retried on the next cycle.
    </p>
  </div>
{/if}

{#if draft}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEditor()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="source-title">
      <div class="spread modal-title">
        <h3 id="source-title" style="margin: 0">
          {draft.originalName ? `Edit Blocklist - ${draft.originalName}` : 'Add Blocklist'}
        </h3>
        <button class="secondary" style="padding: 2px 10px" onclick={closeEditor} aria-label="Close">✕</button>
      </div>

      <div class="form-grid">
        <label>
          <span>Name</span>
          <input bind:value={draft.name} placeholder="StevenBlack Hosts" />
        </label>
        <label>
          <span>Refresh Every</span>
          <select bind:value={draft.refreshHours}>
            {#each REFRESH_OPTIONS as o (o.hours)}
              <option value={o.hours}>{o.label}</option>
            {/each}
          </select>
        </label>
        <label class="wide">
          <span>URL</span>
          <input
            bind:value={draft.url}
            placeholder="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
          />
        </label>
        <label>
          <span>Format</span>
          <select bind:value={draft.format}>
            {#each FORMAT_OPTIONS as o (o.value)}
              <option value={o.value}>{o.label}</option>
            {/each}
          </select>
        </label>
        <label>
          <span>Applies To</span>
          <select bind:value={draft.scope}>
            {#if !draft.scope}
              <option value="" disabled>Choose a replacement scope for this legacy source</option>
            {/if}
            <option value="everyone">Everyone</option>
            <option value="groups">Selected Client Groups Only</option>
          </select>
        </label>
      </div>
      <label class="checkbox"><input type="checkbox" bind:checked={draft.enabled} /> <span>Enabled</span></label>
      <p class="muted help">
        The list is downloaded and checked before it is saved: Auto-Detect
        works out the format, a chosen format must match the content.
        Validate checks it without saving. A list for selected client groups
        only blocks for the groups that tick it on the Client Groups tab.
        Existing DoT-only sources are kept for compatibility; when editing
        one, choose a replacement scope explicitly. For listener-specific
        filtering, create a client group matching DOT, DOH, or DOQ and select
        the source there.
      </p>

      {#if draft.result}
        <div
          class="result"
          style="border-color: {draft.result.ok ? 'var(--ok)' : 'var(--danger)'}"
        >
          {#if draft.result.ok}
            <span class="pill ok">Valid</span>
          {:else}
            <span class="pill err">{draft.result.transport ? 'Unreachable' : 'Invalid'}</span>
          {/if}
          <span class="muted">{draft.result.msg}</span>
        </div>
      {/if}

      <div class="row actions">
        <button onclick={saveSource} disabled={saving}>
          {saving ? 'Saving...' : draft.originalName ? 'Save Blocklist' : 'Add Blocklist'}
        </button>
        <button class="secondary" onclick={validateDraft} disabled={saving}>Validate</button>
        <button class="secondary" onclick={closeEditor} disabled={saving}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .url { font-size: 0.78rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pill-row { display: flex; flex-wrap: wrap; gap: 6px; }
  .fetch-error { font-size: 0.78rem; color: var(--danger); max-width: 320px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(680px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  .checkbox { display: inline-flex; align-items: center; gap: 8px; margin-top: 12px; font-size: 0.85rem; }
  .checkbox input { width: auto; }
  .actions { margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--border); }
  .form-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }
  .form-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  .form-grid label.wide { grid-column: 1 / -1; }
  .form-grid label > span { color: var(--muted); }
  .result {
    margin-top: 12px;
    display: flex;
    align-items: center;
    gap: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
  }
  @media (max-width: 640px) {
    .form-grid { grid-template-columns: 1fr; }
  }
</style>

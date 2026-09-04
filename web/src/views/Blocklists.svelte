<script>
  import { api } from '../api.js';

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
    { value: 'auto', label: 'Auto-detect' },
    { value: 'domains', label: 'Domains (one per line)' },
    { value: 'hosts', label: 'Hosts file (e.g. StevenBlack)' },
    { value: 'adblock', label: 'Adblock (AdGuard / uBlock)' },
  ];
  const REFRESH_OPTIONS = [
    { hours: 1, label: '1 hour' },
    { hours: 6, label: '6 hours' },
    { hours: 12, label: '12 hours' },
    { hours: 24, label: '24 hours' },
    { hours: 72, label: '3 days' },
    { hours: 168, label: '7 days' },
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
      result: null,
    };
  }

  function closeEditor() {
    draft = null;
    error = null;
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
      });

      await api.replaceBlocklistSources(next);
      closeEditor();
      await load();
      notice = `Source "${name}" saved - fetching it now.`;
      // The save triggers a background fetch; poll once until the source's last fetch time updates
      // or a short timeout passes.
      await waitForSourceUpdate(name);
    } catch (e) {
      error = String(e.message || e);
    } finally {
      saving = false;
    }
  }

  async function removeSource(source) {
    if (!confirm(`Delete blocklist source "${source.name}"?`)) return;
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
      error = String(e.message || e);
    }
  }

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

  $effect(() => {
    load();
  });
</script>

<h1>Blocklists</h1>
<p class="muted" style="max-width: 75ch">
  Fetch remote blocklists (domain lists, hosts files or adblock filters) and
  merge them into the blocklist. Add, edit and remove sources below - changes
  are saved to <code>daygle-dns.toml</code> and applied to the running server
  immediately. Sources are validated before they are saved.
</p>

<div class="row" style="margin-bottom: 14px">
  <button onclick={openAdd}>Add source</button>
  <button class="secondary" onclick={refreshNow} disabled={refreshing || !configured}>
    {refreshing ? 'Refreshing…' : 'Refresh Now'}
  </button>
  <button class="secondary" onclick={load}>Refresh</button>
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
    <p class="muted" style="max-width: 70ch">
      Add your first source to start blocking from a remote list. Give it a
      name, paste the URL, and pick the content format - or leave the format
      on <strong>Auto-detect</strong> and the server will work it out from the
      fetched content before the source is saved.
    </p>
    <div class="row">
      <button onclick={openAdd}>Add your first source</button>
    </div>
    <pre><code>name        e.g. "StevenBlack hosts"
url         https://…/hosts
format      domains | hosts | adblock  (or auto-detect)
refresh     every 1h … 7d</code></pre>
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
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each sources as s (s.url)}
          <tr class:disabled={!s.enabled}>
            <td>
              <strong>{s.name}</strong>
              <div class="muted" style="font-size: 0.78rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">
                {s.url}
              </div>
            </td>
            <td><span class="pill">{s.format}</span></td>
            <td class="muted">{Math.round(s.refresh_secs / 3600)} h</td>
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
            <td class="num">
              <button class="secondary" onclick={() => openEdit(s)}>Edit</button>
              <button class="danger" onclick={() => removeSource(s)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  <p class="muted" style="font-size: 0.8rem">
    Refresh Now fetches every source immediately. Sources also refresh
    automatically on their configured interval; a failed fetch is reported
    here and retried on the next cycle.
  </p>
{/if}

<!-- Source editor -->
{#if draft}
  <div class="card" style="border-color: var(--accent); margin-bottom: 14px">
    <div class="spread">
      <h3 style="margin: 0">
        {draft.originalName ? `Edit "${draft.originalName}"` : 'New source'}
      </h3>
      <label class="check">
        <input type="checkbox" bind:checked={draft.enabled} /> <span>Enabled</span>
      </label>
    </div>

    <div class="form-grid" style="margin-top: 12px">
      <label>
        <span>Name</span>
        <input bind:value={draft.name} placeholder="StevenBlack hosts" />
      </label>
      <label>
        <span>Refresh interval</span>
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
      <label class="wide">
        <span>Format</span>
        <select bind:value={draft.format}>
          {#each FORMAT_OPTIONS as o (o.value)}
            <option value={o.value}>{o.label}</option>
          {/each}
        </select>
        <small class="muted">
          Auto-detect probes the URL and picks hosts, domains or adblock from
          the content. Picking a concrete format also checks the content
          matches before saving.
        </small>
      </label>
    </div>

    {#if draft.result}
      <div
        class="result"
        style="border-color: {draft.result.ok ? 'var(--ok)' : 'var(--danger)'}"
      >
        {#if draft.result.ok}
          <span class="pill ok">valid</span>
        {:else}
          <span class="pill err">{draft.result.transport ? 'unreachable' : 'invalid'}</span>
        {/if}
        <span class="muted">{draft.result.msg}</span>
      </div>
    {/if}

    <div class="row" style="margin-top: 12px">
      <button onclick={saveSource} disabled={saving}>
        {saving ? 'Saving…' : draft.originalName ? 'Save changes' : 'Add source'}
      </button>
      <button class="secondary" onclick={validateDraft}>
        Validate source
      </button>
      <button class="secondary" onclick={closeEditor}>Cancel</button>
    </div>
  </div>
{/if}

<style>
  tr.disabled { opacity: 0.55; }
  .pill.ok { color: var(--ok); border-color: var(--ok); }
  .pill.err { color: var(--danger); border-color: var(--danger); }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { font-size: 0.78rem; color: var(--muted); font-weight: 600; }
  .num { text-align: right; white-space: nowrap; }
  .check { display: inline-flex; align-items: center; gap: 6px; }
  .form-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }
  .form-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  .form-grid label.wide { grid-column: 1 / -1; }
  .form-grid label > span { color: var(--muted); }
  .form-grid small { font-size: 0.78rem; }
  .result {
    margin-top: 12px;
    display: flex;
    align-items: center;
    gap: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
  }
  pre {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    overflow: auto;
    font-size: 0.8rem;
    margin-bottom: 0;
  }
  @media (max-width: 640px) {
    .form-grid { grid-template-columns: 1fr; }
  }
</style>

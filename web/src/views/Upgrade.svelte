<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { onDestroy } from 'svelte';

  let info = $state(null);
  let error = $state(null);
  let busy = $state(false);
  let copied = $state(false);

  const isAdmin = getStoredUser()?.role === 'admin';

  // In-place update run state (mirrors the server's UpgradeState).
  let run = $state(null);
  let logTail = $state('');
  let updating = $state(false); // we started (or resumed polling) a run
  let serverDown = $state(false); // the API went away mid-run (restarting)
  let startError = $state('');
  let iStarted = $state(false); // this session triggered the current run

  const RUNNING = ['preparing', 'cloning', 'building', 'installing'];
  const PHASE_LABEL = {
    preparing: 'Preparing…',
    cloning: 'Fetching source…',
    building: 'Building release binary (a few minutes)…',
    installing: 'Installing new binary…',
    done: 'Complete',
    error: 'Failed',
  };

  function runRunning() {
    return run && RUNNING.includes(run.phase);
  }

  let pollTimer = null;
  let reloadTimer = null;
  onDestroy(() => {
    clearTimeout(pollTimer);
    clearTimeout(reloadTimer);
  });

  function poll() {
    clearTimeout(pollTimer);
    api
      .upgradeStatus()
      .then((st) => {
        serverDown = false;
        run = st.state;
        logTail = st.log || '';
        if (runRunning()) {
          pollTimer = setTimeout(poll, 1500);
        } else {
          updating = false;
          // The run we triggered finished and the fresh binary is live:
          // bring the operator back to the reloaded console.
          if (iStarted && run?.phase === 'done' && !reloadTimer) {
            reloadTimer = setTimeout(reloadConsole, 4000);
          }
        }
      })
      .catch(() => {
        // The updater restarted the server: the API is briefly unreachable.
        serverDown = true;
        pollTimer = setTimeout(poll, 1000);
      });
  }

  function reloadConsole() {
    location.reload();
  }

  async function load() {
    busy = true;
    error = null;
    try {
      info = await api.upgradeInfo();
      run = info?.state ?? null;
      // Server can come back in the middle of a run started elsewhere (or a
      // previous session); resume following it.
      if (runRunning()) poll();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    load();
  });

  async function startUpdate() {
    startError = '';
    const ok = confirm(
      'Update Daygle DNS to the latest source?\n\nThe server will build a new release binary, swap it in place and restart. DNS resolution is briefly interrupted and this console may take a moment to reconnect.'
    );
    if (!ok) return;
    try {
      await api.upgradeStart();
      iStarted = true;
      updating = true;
      serverDown = false;
      poll();
    } catch (e) {
      startError = formatApiError(e);
    }
  }

  async function copyCommand() {
    if (!info) return;
    try {
      await navigator.clipboard.writeText(info.upgrade_command);
      copied = true;
      setTimeout(() => {
        copied = false;
      }, 2000);
    } catch (e) {
      error = formatApiError(e);
    }
  }
</script>

<h1>Upgrade</h1>

<p class="muted" style="max-width: 75ch">
  The recommended way to update all components is the project's in-place
  update, which mirrors the one-line installer: it fetches the latest source,
  rebuilds the server binary, installs it in place, and preserves your
  configuration, zones, certificates, and database. On qualifying hosts you
  can trigger it right from here; elsewhere it runs as a one-liner on the host.
</p>

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if info}

  <!-- self-update available -->
  {#if info.can_update}
    <div class="card" style="margin-bottom: 14px">
      <div class="spread">
        <h3 style="margin: 0">In-Place Update</h3>
        {#if updating || runRunning()}
          <span class="pill"><span class="spin" aria-hidden="true"></span> Updating…</span>
        {:else if run?.phase === 'done'}
          <span class="pill ok">Complete</span>
        {:else if run?.phase === 'error'}
          <span class="pill err">Failed</span>
        {/if}
      </div>

      {#if startError}
        <div class="form-error" style="margin-bottom: 10px">{startError}</div>
      {/if}

      {#if updating || runRunning()}
        <p style="margin: 8px 0">
          <strong>{run?.message || PHASE_LABEL[run?.phase] || 'Working…'}</strong>
        </p>
        {#if serverDown}
          <div class="form-error" style="margin: 8px 0">
            The server is restarting with the new build — reconnecting…
          </div>
        {/if}
        {#if logTail}
          <pre class="log">{logTail}</pre>
        {/if}

      {:else if run?.phase === 'done'}
        <p style="margin: 8px 0">
          <span class="pill ok">✓</span> Update complete — the server restarted with the latest build.
        </p>
        <button class="secondary" onclick={reloadConsole} style="margin-top: 8px">
          Reload console
        </button>
        <p class="muted" style="font-size: 0.8rem; margin-top: 10px">
          Reloading in a few seconds automatically.
        </p>

      {:else if run?.phase === 'error'}
        <p style="margin: 8px 0; color: var(--danger)">
          The update failed: {run.message}
        </p>
        {#if logTail}
          <pre class="log">{logTail}</pre>
        {/if}
        <button class="secondary" onclick={load} style="margin-top: 8px">Dismiss</button>

      {:else}
        {#if isAdmin}
          <button onclick={startUpdate} disabled={busy}>Update Now</button>
        {:else}
          <p class="muted" style="font-size: 0.85rem">
            Read-only console accounts cannot start an update; ask an
            administrator.
          </p>
        {/if}
      {/if}

      {#if run?.started_at}
        <p class="muted" style="font-size: 0.78rem; margin-top: 10px">
          Last run: {run.started_at} · pid {run.pid} · exit {run.exit_code}
        </p>
      {/if}
    </div>
  {/if}

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Current Installation</h3>
    <div class="form-grid">
      <label><span>Installed Version</span><code>{info.version}</code></label>
      <label><span>Config File</span>{info.has_config_file ? 'Detected' : 'Not detected'}</label>
      <label><span>Service Manager</span>{info.has_systemd ? 'systemd' : 'Not detected'}</label>
      <label><span>In-Place Update</span>{info.can_update ? 'Available' : 'Not available on this host'}</label>
    </div>
    {#if !info.can_update}
      <p class="muted" style="font-size: 0.82rem; margin: 10px 0 0; max-width: 80ch">
        In-place updates need a Linux host with git and cargo, plus a binary
        managed by the installer (systemd unit, <code>/usr/local/bin</code>,
        or a config under <code>/etc</code>). Otherwise use the host command
        below.
      </p>
    {/if}
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Upgrade Command</h3>
    <p class="muted" style="font-size: 0.85rem; margin-bottom: 10px">
      Run this on the host to update all components the same way
      <code>install.sh</code> does.
    </p>
    <div class="command-block">
      <code>{info.upgrade_command}</code>
      <button class="secondary" onclick={copyCommand} disabled={copied || busy}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
    {#if info.note}
      <p class="muted" style="font-size: 0.85rem; margin-top: 10px">{info.note}</p>
    {/if}
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Preserved During Upgrade</h3>
    <div class="preserve-list">
      {#each info.preserves as item}
        <span class="preserve">{item}</span>
      {/each}
    </div>
    <p class="muted" style="font-size: 0.85rem; margin-top: 10px">
      The one-line installer is available directly from the project repository:
      <a href={info.install_script} target="_blank" rel="noreferrer">{info.install_script}</a>
    </p>
  </div>

  <div class="card">
    <h3 style="margin-top: 0">Runtime Status</h3>
    <table>
      <tbody>
        <tr><td class="muted">Version</td><td><code>{info.version}</code></td></tr>
      </tbody>
    </table>
  </div>
{:else if busy}
  <p class="muted">Loading upgrade details…</p>
{/if}

<style>
  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 12px;
    align-items: end;
  }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  code { font: inherit; color: var(--text); }
  .command-block {
    display: flex;
    gap: 8px;
    align-items: stretch;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
  }
  .command-block code {
    flex: 1;
    font: 0.85rem/1.5 ui-monospace, 'Cascadia Code', Consolas, monospace;
    word-break: break-all;
  }
  .command-block button {
    align-self: stretch;
    padding: 6px 12px;
    font-size: 0.8rem;
    white-space: nowrap;
  }
  .preserve-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 6px;
  }
  .preserve {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 0.85rem;
  }
  table { width: 100%; border-collapse: collapse; }
  td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
  td:first-child { width: 52%; }
  .spread { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
  .spin {
    display: inline-block;
    width: 10px;
    height: 10px;
    margin-right: 6px;
    border: 2px solid var(--border);
    border-top-color: var(--text);
    border-radius: 50%;
    vertical-align: middle;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  .log {
    max-height: 220px;
    overflow: auto;
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px;
    margin: 10px 0 0;
    font: 0.75rem/1.4 ui-monospace, 'Cascadia Code', Consolas, monospace;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--text);
  }
</style>
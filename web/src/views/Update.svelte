<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { onDestroy } from 'svelte';

  let info = $state(null);
  let error = $state(null);
  let busy = $state(false);
  let copied = $state(false);

  const isAdmin = getStoredUser()?.role === 'admin';

  // In-place update run state (mirrors the server's UpdateState).
  let run = $state(null);
  let logTail = $state('');
  let updating = $state(false); // we started (or resumed polling) a run
  let serverDown = $state(false); // the API went away mid-run (restarting)
  let startError = $state('');
  let iStarted = $state(false); // this session triggered the current run

  // Pre-flight health check state
  let preflightResult = $state(null);
  let preflightLoading = $state(false);
  let preflightError = $state('');

  const RUNNING = ['preparing', 'downloading', 'cloning', 'building', 'installing', 'applying', 'restarting'];
  const PHASE_LABEL = {
    preparing: 'Preparing…',
    downloading: 'Downloading the prebuilt release…',
    cloning: 'Fetching source (no prebuilt release matched, building from source)…',
    building: 'Building release binary (a few minutes)…',
    installing: 'Installing new binary…',
    applying: 'Applying the new release…',
    restarting: 'Restarting the service…',
    checking: 'Verifying update…',
    rolling_back: 'Rolling back to previous version…',
    done: 'Complete',
    error: 'Failed',
  };

  function runRunning() {
    return run && RUNNING.includes(run.phase);
  }

  // A successful rollback is a terminal state recorded with phase "done"
  // (archived update.sh versions) even though the update failed. Treat it as
  // a failure so the console offers Dismiss/retry instead of a dead-end
  // "Complete" view with only a Reload button.
  function isRollback(run) {
    return run?.phase === 'done' && /successfully rolled back/i.test(run.message || '');
  }

  let autoDismissTimer = null;

  // Give the completion card a few seconds on screen after a successful
  // update, then clear the recorded run so the console falls back to the
  // actionable state (Update Now / banner). Rollbacks and errors keep
  // waiting for the user to act.
  $effect(() => {
    if (run?.phase === 'done' && !isRollback(run)) {
      if (autoDismissTimer) return;
      autoDismissTimer = setTimeout(() => {
        autoDismissTimer = null;
        dismissRun();
      }, 12000);
    }
  });

  let pollTimer = null;
  let reloadTimer = null;
  // Set while we are waiting for the restarted service to answer before
  // reloading the console.
  let waitingForServer = $state(false);
  onDestroy(() => {
    waitingForServer = false;
    clearTimeout(pollTimer);
    clearTimeout(reloadTimer);
    clearTimeout(autoDismissTimer);
  });

  function poll() {
    clearTimeout(pollTimer);
    api
      .updateStatus()
      .then((st) => {
        serverDown = false;
        run = st.state;
        logTail = st.log || '';
        if (runRunning()) {
          pollTimer = setTimeout(poll, 1500);
        } else {
          updating = false;
          // The run we triggered finished; the helper restarts the service
          // right after installing, so wait for it to answer before
          // reloading instead of landing on a connection-refused page.
          if (iStarted && run?.phase === 'done' && !isRollback(run)) {
            scheduleReload();
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
    // A manual reload is a deliberate "move on" action: clear the recorded
    // run snapshot as well, so the console comes back actionable instead of
    // re-showing the done/error card. The auto-reload after an update goes
    // through pingServer() below and deliberately keeps the snapshot so the
    // completion confirmation is still visible.
    api
      .updateDismiss()
      .then(() => location.reload())
      .catch(() => location.reload());
  }

  function scheduleReload() {
    if (waitingForServer) return;
    waitingForServer = true;
    // Clear poll timer to avoid unnecessary requests during reload
    clearTimeout(pollTimer);
    reloadTimer = setTimeout(pingServer, 4000);
  }

  function pingServer() {
    if (!waitingForServer) return;
    // Any HTTP response - even 401 - means the API is back up.
    fetch('/api/auth/setup', { cache: 'no-store' })
      .then(() => {
        location.reload();
      })
      .catch(() => {
        if (waitingForServer) reloadTimer = setTimeout(pingServer, 1500);
      });
  }

  async function runPreflight() {
    preflightLoading = true;
    preflightError = '';
    try {
      preflightResult = await api.updatePreflight();
    } catch (e) {
      preflightError = formatApiError(e);
    } finally {
      preflightLoading = false;
    }
  }

  async function load() {
    busy = true;
    error = null;
    try {
      info = await api.updateInfo();
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
    
    // Run pre-flight checks first
    await runPreflight();
    if (preflightResult && !preflightResult.ready) {
      // Show pre-flight errors instead of proceeding
      return;
    }
    
    const ok = confirm(
      'Update Daygle DNS to the latest release?\n\nThe server will download the latest prebuilt release, verify its checksum, swap it in place and restart. DNS resolution is briefly interrupted and this console may take a moment to reconnect.'
    );
    if (!ok) return;
    updating = true; // guard against double-clicks while the request is out
    try {
      await api.updateStart();
      iStarted = true;
      serverDown = false;
      preflightResult = null; // Clear pre-flight results on successful start
      poll();
    } catch (e) {
      updating = false;
      startError = formatApiError(e);
    }
  }

  // Clear the recorded run state on the server so the last done/error
  // result stops being shown. A dismiss while a run is active is refused
  // (409) and surfaces through startError.
  async function dismissRun() {
    clearTimeout(autoDismissTimer);
    autoDismissTimer = null;
    startError = '';
    try {
      await api.updateDismiss();
      run = null;
      logTail = '';
      await load();
    } catch (e) {
      startError = formatApiError(e);
    }
  }

  async function copyCommand() {
    if (!info) return;
    try {
      await navigator.clipboard.writeText(info.update_command);
      copied = true;
      setTimeout(() => {
        copied = false;
      }, 2000);
    } catch (e) {
      error = formatApiError(e);
    }
  }
</script>

<PageHeader
  icon={icons.update}
  title="Update"
  tagline="The recommended way to update all components is the project's in-place update. It downloads the latest prebuilt release, verifies its checksum, installs it in place, and preserves your configuration, zones, certificates, and database - no Rust toolchain is required on the host. (When no prebuilt release matches, it falls back to building from source.) The privileged install step runs as its own dedicated systemd service, so the server account never needs root rights. On qualifying hosts you can trigger it right from here; elsewhere it runs as a one-liner on the host."
/>

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
        {:else if run?.phase === 'done' && isRollback(run)}
          <span class="pill err">Failed</span>
        {:else if run?.phase === 'done'}
          <span class="pill ok">Complete</span>
        {:else if run?.phase === 'error'}
          <span class="pill err">Failed</span>
        {/if}
      </div>

      {#if startError}
        <div class="form-error" style="margin-bottom: 10px">{startError}</div>
      {/if}

      {#if preflightResult && !preflightResult.ready}
        <div class="preflight-card">
          <h4 style="margin: 0 0 10px">Pre-flight Check Results</h4>
          <p class="muted" style="font-size: 0.85rem; margin-bottom: 10px">
            The following issues were detected. Please fix them before attempting an update.
          </p>
          {#each preflightResult.checks as check}
            <div class="preflight-check" class:failed={!check.ok}>
              <div class="preflight-header">
                <span class="preflight-icon">{check.ok ? '✓' : '✗'}</span>
                <strong>{check.name}</strong>
              </div>
              <p class="preflight-message">{check.message}</p>
              {#if check.fix}
                <div class="preflight-fix">
                  <strong>How to fix:</strong> {check.fix}
                </div>
              {/if}
              {#if check.fix_commands}
                <div class="preflight-commands">
                  <strong>Commands to run:</strong>
                  <pre>{check.fix_commands.join('\n')}</pre>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {:else if preflightError}
        <div class="form-error" style="margin-bottom: 10px">{preflightError}</div>
      {/if}

      {#if info.updater_bootstrap_required}
        <div class="bootstrap">
          <p style="margin: 0">
            <strong>One-time bootstrap needed:</strong> the installed updater
            (from version {info.version}) predates the release-download update
            path, so an update started here cannot complete on this host. Run
            the installer command in the Manual Update Command card below once
            - it swaps in the new binary and provisions the update helper -
            and one-click updates work from then on.
          </p>
        </div>
      {:else if info.updater_outdated && info.latest_release}
        <p class="muted" style="font-size: 0.82rem; margin: 8px 0 0">
          A newer release (v{info.latest_release}) is available; the installed
          version is {info.version}.
        </p>
      {/if}

      {#if updating || runRunning()}
        <p style="margin: 8px 0">
          <strong>{run?.message || PHASE_LABEL[run?.phase] || 'Working…'}</strong>
        </p>
        {#if serverDown}
          <div class="form-error" style="margin: 8px 0">
            The server is restarting with the new build - reconnecting…
          </div>
        {/if}
        {#if logTail}
          <pre class="log">{logTail}</pre>
        {/if}

      {:else if run?.phase === 'done'}
        {#if isRollback(run)}
          <p style="margin: 8px 0; color: var(--danger)">The update failed: {run.message}</p>
          <div style="display: flex; gap: 8px; margin-top: 8px">
            <button class="secondary" onclick={dismissRun}>Dismiss</button>
            <button class="secondary" onclick={reloadConsole}>Reload Console</button>
          </div>
        {:else}
          <p style="margin: 8px 0">
            <span style="color: var(--ok)">✓</span> {run?.message || 'Update complete.'}
          </p>
          <div style="display: flex; gap: 8px; margin-top: 8px">
            <button class="secondary" onclick={reloadConsole}>Reload Console</button>
            <button class="secondary" onclick={dismissRun}>Dismiss</button>
          </div>
          {#if waitingForServer}
            <p class="muted" style="font-size: 0.8rem; margin-top: 10px">
              Waiting for the restarted service to come back, then reloading automatically…
            </p>
          {/if}
        {/if}

      {:else if run?.phase === 'error'}
        <p style="margin: 8px 0; color: var(--danger)">
          The update failed: {run.message}
        </p>
        {#if logTail}
          <pre class="log">{logTail}</pre>
        {/if}
        <button class="secondary" onclick={dismissRun} style="margin-top: 8px">Dismiss</button>

      {:else if info.updater_bootstrap_required}
        <p class="muted" style="font-size: 0.85rem; margin: 8px 0 0">
          Complete the one-time bootstrap above to enable in-place updates
          from this page.
        </p>
      {:else}
        {#if isAdmin}
          <div style="display: flex; gap: 8px; margin-top: 8px">
            <button onclick={startUpdate} disabled={busy || updating || preflightLoading}>Update Now</button>
            <button class="secondary" onclick={runPreflight} disabled={busy || updating || preflightLoading}>
              {preflightLoading ? 'Checking…' : 'Check Health'}
            </button>
          </div>
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
    <table>
      <tbody>
        <tr><td class="muted">Installed Version</td><td><code>{info.version}</code></td></tr>
        <tr><td class="muted">Latest Release</td><td>{#if info.latest_release}<code>v{info.latest_release}</code>{:else}Unknown{/if}</td></tr>
        <tr><td class="muted">Config File</td><td>{info.has_config_file ? 'Detected' : 'Not detected'}</td></tr>
        <tr><td class="muted">Service Manager</td><td>{info.has_systemd ? 'systemd' : 'Not detected'}</td></tr>
        <tr><td class="muted">In-Place Update</td><td>{info.can_update ? 'Available' : 'Not available on this host'}</td></tr>
      </tbody>
    </table>
    {#if !info.can_update}
      <p class="muted" style="font-size: 0.82rem; margin: 10px 0 0; max-width: 80ch">
        In-place updates need a Linux host managed by the installer (systemd
        unit, <code>/usr/local/bin/daygle-dns</code>, or a config under
        <code>/etc</code>) and a downloader (curl or wget) for the prebuilt
        release. Otherwise use the host command below. Missing requirements:
      </p>
      <ul class="gates" style="font-size: 0.82rem; margin: 8px 0 0">
        {#each info.gates || [] as gate}
          <li>{gate}</li>
        {/each}
      </ul>
    {/if}
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Manual Update Command</h3>
    <p class="muted" style="font-size: 0.85rem; margin-bottom: 10px">
      Run this on the host to update all components the same way
      <code>install.sh</code> does.
    </p>
    <div class="command-block">
      <code>{info.update_command}</code>
      <button class="secondary" onclick={copyCommand} disabled={copied || busy}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
    {#if info.note}
      <p class="muted" style="font-size: 0.85rem; margin-top: 10px">{info.note}</p>
    {/if}
    <p class="muted" style="font-size: 0.85rem; margin-top: 10px">
      The one-line installer is available directly from the project repository:
      <a href={info.install_script} target="_blank" rel="noreferrer">{info.install_script}</a>
    </p>
  </div>

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Preserved During Update</h3>
    <div class="preserve-list">
      {#each info.preserves as item}
        <span class="preserve">{item}</span>
      {/each}
    </div>
  </div>
{:else if busy}
  <p class="muted">Loading update details…</p>
{/if}

<style>
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
  .bootstrap {
    background: var(--panel-2);
    border: 1px solid var(--warn, #b58900);
    border-radius: 6px;
    padding: 10px 12px;
    margin: 10px 0;
    font-size: 0.88rem;
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
  .preflight-card {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    margin: 10px 0;
  }
  .preflight-check {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    margin: 8px 0;
    background: var(--panel);
  }
  .preflight-check.failed {
    border-color: var(--danger, #dc3545);
    background: rgba(220, 53, 69, 0.05);
  }
  .preflight-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }
  .preflight-icon {
    font-weight: bold;
    color: var(--muted);
  }
  .preflight-check.failed .preflight-icon {
    color: var(--danger, #dc3545);
  }
  .preflight-message {
    margin: 0;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .preflight-fix {
    margin-top: 8px;
    padding: 8px;
    background: var(--panel-2);
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .preflight-commands {
    margin-top: 8px;
  }
  .preflight-commands pre {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px;
    margin: 4px 0 0;
    font: 0.8rem/1.4 ui-monospace, 'Cascadia Code', Consolas, monospace;
    white-space: pre-wrap;
    overflow-x: auto;
  }
</style>
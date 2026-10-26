<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { onDestroy } from 'svelte';
  import { formatDateTime } from '../datetime.svelte.js';
  import { copyText } from '../clipboard.js';
  import UpdateChecks from './UpdateChecks.svelte';

  let info = $state(null);
  let error = $state(null);
  let busy = $state(false);
  let copied = $state(false);

  // Viewers are read-only; with sign-in off there is no stored user at all.
  const isAdmin = getStoredUser()?.role !== 'viewer';

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

  // Must match UpdateState::is_running on the server.
  const RUNNING = ['preparing', 'downloading', 'cloning', 'building', 'installing', 'applying', 'restarting', 'rolling_back'];
  const PHASE_LABEL = {
    preparing: 'Preparing the update...',
    downloading: 'Fetching the installer...',
    cloning: 'Fetching the source...',
    building: 'Building the release...',
    installing: 'Handing off to the update service...',
    applying: 'Running the installer (several minutes; the build happens here)...',
    restarting: 'Restarting the service...',
    rolling_back: 'Rolling back to previous version...',
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
    clearTimeout(checkNoteTimer);
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
      .catch((e) => {
        // Signed out or not allowed: polling again cannot succeed.
        if (e?.status === 401 || e?.status === 403) {
          updating = false;
          startError = formatApiError(e);
          return;
        }
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
      'Update Daygle DNS to the latest release?\n\nThe server will run the same one-line installer you can run by hand: it fetches the latest release, builds it from source, installs it and re-provisions the systemd services. Your configuration (including the listen address), zones, certificates and database are kept. The build can take several minutes on a small host; DNS resolution is briefly interrupted and this console may take a moment to reconnect.'
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

  // Formats whole seconds as a short human duration for the last-check line:
  // "45 s", "12 min", "3 h".
  function formatAgeSecs(secs) {
    if (secs == null) return null;
    if (secs < 90) return `${Math.round(secs)} s`;
    if (secs < 90 * 60) return `${Math.round(secs / 60)} min`;
    return `${Math.round(secs / 3600)} h`;
  }

  // Details shown as a tooltip on the header status pill: what is installed,
  // what is out there, and how fresh the release check is.
  function releaseTooltip() {
    if (!info) return '';
    const latest = info.latest_release ? `v${info.latest_release}` : 'unknown';
    let when;
    if (info.latest_checked_secs_ago == null) {
      when = 'no release check has run since the server started';
    } else {
      when = `last release check ran ${formatAgeSecs(info.latest_checked_secs_ago)} ago`;
    }
    if (info.checks_enabled && info.check_interval_secs) {
      when += ` (automatic checks run every ${formatAgeSecs(info.check_interval_secs)})`;
    } else {
      when += ' (automatic release checks are off)';
    }
    return `Installed v${info.version} · latest release ${latest} · ${when}`;
  }

  // Tooltip for the update-run pills: when the run started and, once it has
  // ended, how it ended.
  function runTooltip() {
    if (!run?.started_at) return undefined;
    let text = `Update started ${formatDateTime(run.started_at)}`;
    if (run.phase === 'done' || run.phase === 'error') {
      text += ` · finished with exit code ${run.exit_code}`;
    }
    return text;
  }

  // Operator-triggered release fetch ("Check Now"): resolves the worst
  // case of the automatic cadence (a fresh release staying invisible for a
  // whole check interval). The server throttles live fetches to one per
  // minute; a request inside that window comes back with the cached value
  // `retry_after_secs` seconds after the last live one.
  let checking = $state(false);
  let checkNote = $state('');
  let checkNoteTimer = null;

  async function checkNow() {
    checking = true;
    checkNote = '';
    try {
      const res = await api.updateCheck();
      await load();
      checkNote = res.checked_now
        ? res.fetched
          ? 'Release check ran against GitHub just now.'
          : 'Release check just ran, but GitHub could not be reached (or was rate-limited); the value shown may be stale.'
        : `The last live check was under a minute ago; the next one can run in ${formatAgeSecs(res.retry_after_secs)} - showing that earlier result.`;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      checking = false;
      clearTimeout(checkNoteTimer);
      checkNoteTimer = setTimeout(() => {
        checkNote = '';
      }, 8000);
    }
  }

  async function copyCommand() {
    if (!info) return;
    try {
      await copyText(info.update_command);
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
  tagline="Update Daygle DNS in place. Update Now runs the same one-line installer you would run by hand: the latest release is built from source and installed, the systemd services re-provisioned, and your configuration, zones, certificates and database are kept."
/>


{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if info}

  {#snippet installFooter(divided)}
    <div class="version-row" class:divided>
      <div class="version-stat">
        <span class="v-label">Installed Version</span>
        <code>v{info.version}</code>
      </div>
      <div class="version-stat">
        <span class="v-label">Latest Release</span>
        {#if info.latest_release}<code>v{info.latest_release}</code>{:else}Unknown{/if}
      </div>
    </div>
    {#if checkNote}
      <p class="muted small" style="margin: 8px 0 0">{checkNote}</p>
    {/if}
    {#if info.checks_enabled && info.check_interval_secs}
      <p class="muted small" style="margin: 10px 0 0; max-width: 80ch">
        Automatic checks run every {formatAgeSecs(info.check_interval_secs)}
        {#if info.latest_checked_secs_ago == null}
          - none has run since the server started.
        {:else}
          - the last one ran {formatAgeSecs(info.latest_checked_secs_ago)} ago.
        {/if}
      </p>
    {:else}
      <p class="muted small" style="margin: 10px 0 0; max-width: 80ch">
        Automatic release checks are off (Settings &rarr; General). Any latest
        release shown above came from a manual check.
      </p>
    {/if}
    {#if !info.can_update}
      <p class="muted small" style="margin: 10px 0 0; max-width: 80ch">
        In-place updates need a Linux host managed by the installer (systemd
        unit, <code>/usr/local/bin/daygle-dns</code>, or a config under
        <code>/etc</code>) and a way to fetch the installer (curl or wget,
        or git). Otherwise use the host command below. Missing requirements:
      </p>
      <ul class="gates small" style="margin: 8px 0 0">
        {#each info.gates || [] as gate}
          <li>{gate}</li>
        {/each}
      </ul>
    {/if}
  {/snippet}

  <!-- self-update available -->
  {#if info.can_update}
    <div class="card" style="margin-bottom: 14px">
      <div class="spread">
        <div class="title-row">
          <h3 style="margin: 0">Update</h3>
          {#if updating || runRunning()}
            <span class="pill" title={runTooltip()}
              ><span class="spin" aria-hidden="true"></span> Updating...</span
            >
          {:else if run?.phase === 'done' && isRollback(run)}
            <span class="pill err" title={runTooltip()}>Failed</span>
          {:else if run?.phase === 'done'}
            <span class="pill ok" title={runTooltip()}>Complete</span>
          {:else if run?.phase === 'error'}
            <span class="pill err" title={runTooltip()}>Failed</span>
          {:else if info.updater_outdated === false}
            <span class="pill ok" title={releaseTooltip()}>Up to date</span>
          {:else if info.updater_outdated}
            <span class="pill new" title={releaseTooltip()}>Update available</span>
          {/if}
        </div>
        {#if isAdmin}
          <button
            class="secondary"
            style="font-size: 0.8rem; padding: 5px 12px; white-space: nowrap"
            onclick={checkNow}
            disabled={checking}
            title="Fetch the latest published release from GitHub now (at most one live check per minute)"
          >
            {checking ? 'Checking...' : 'Check Now'}
          </button>
        {/if}
      </div>

      {#if startError}
        <div class="form-error" style="margin-bottom: 10px">{startError}</div>
      {/if}

      {#if preflightResult?.ready}
        <p class="health-ok">
          ✓ All {preflightResult.checks?.length || ''} health checks passed. This host is ready to update.
        </p>
      {:else if preflightResult && !preflightResult.ready}
        <div class="preflight-card">
          <h4 style="margin: 0 0 10px">Pre-Flight Check Results</h4>
          <p class="muted small" style="margin-bottom: 10px">
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
            (from version {info.version}) predates the in-place updater, so an
            update started here cannot complete on this host. Run the installer
            command in the Manual Update Command card below once - it installs
            the latest build and provisions the update helper - and one-click
            updates (which then run the same installer for you) work from then
            on.
          </p>
        </div>
      {:else if info.updater_outdated && info.latest_release}
        <p class="muted small" style="margin: 8px 0 0">
          A newer release (v{info.latest_release}) is available; the installed
          version is {info.version}.
        </p>
      {/if}

      {#if updating || runRunning()}
        <p style="margin: 8px 0">
          <strong>{run?.message || PHASE_LABEL[run?.phase] || 'Working...'}</strong>
        </p>
        {#if serverDown}
          <div class="form-error" style="margin: 8px 0">
            The server is restarting with the new build - reconnecting...
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
            <p class="muted small" style="margin-top: 10px">
              Waiting for the restarted service to come back, then reloading automatically...
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
        <p class="muted small" style="margin: 8px 0 0">
          Complete the one-time bootstrap above to enable in-place updates
          from this page.
        </p>
      {:else if info.updater_outdated === false}
        <p class="muted small" style="margin: 8px 0 0">
          No newer release is available; the installed version ({info.version}) is up to date.
        </p>
      {:else}
        {#if isAdmin}
          <div style="display: flex; gap: 8px; margin-top: 8px">
            <button onclick={startUpdate} disabled={busy || updating || preflightLoading}>Update Now</button>
            <button class="secondary" onclick={runPreflight} disabled={busy || updating || preflightLoading}>
              {preflightLoading ? 'Checking...' : 'Check Health'}
            </button>
          </div>
        {:else}
          <p class="muted small">
            Read-only console accounts cannot start an update; ask an
            administrator.
          </p>
        {/if}
      {/if}

      {#if run?.started_at}
        <p class="muted small" style="margin-top: 10px" title="Process {run.pid}{run.phase === 'done' || run.phase === 'error' ? `, exit code ${run.exit_code}` : ''}">
          Last update started {formatDateTime(run.started_at)}.
        </p>
      {/if}

      {@render installFooter(true)}
    </div>
  {:else}
    <!-- self-update unavailable -->
    <div class="card" style="margin-bottom: 14px">
      <h3 style="margin: 0">Current Installation</h3>
      {@render installFooter(false)}
    </div>
  {/if}

  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 10px">Manual Update Command</h3>
    <p class="muted small" style="margin-bottom: 10px">
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
      <p class="muted small" style="margin-top: 10px">{info.note}</p>
    {/if}
    <p class="muted small" style="margin-top: 10px">
      The one-line installer is available directly from the project repository:
      <a href={info.install_script} target="_blank" rel="noreferrer">{info.install_script}</a>
    </p>
  </div>
{:else if busy}
  <div class="card">
    <p class="muted">Loading update details...</p>
  </div>
{/if}

{#if isAdmin}
  <UpdateChecks />
{/if}

<style>
  code { font: inherit; color: var(--text); }
  .health-ok { color: var(--ok); margin: 10px 0 0; }
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
  .spread { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
  .title-row { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .version-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 28px;
    margin-top: 14px;
  }
  .version-row.divided {
    border-top: 1px solid var(--border);
    padding-top: 12px;
  }
  .version-stat {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 0.9rem;
  }
  .v-label { color: var(--muted); }
  .pill.new { color: var(--warn, #b58900); border-color: var(--warn, #b58900); }
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
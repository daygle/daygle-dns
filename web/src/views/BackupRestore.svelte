<script>
  import { onMount } from 'svelte';
  import { api, formatApiError } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';

  // Settings -> Backup: download a backup of the database, and stage one to
  // restore on the next restart. Independent of the Settings form.
  let includeLogs = $state(false);
  let downloading = $state(false);
  let pending = $state(null);
  let file = $state(null);
  let restoring = $state(false);
  let notice = $state(null);
  let error = $state(null);

  onMount(async () => {
    try {
      pending = (await api.pendingRestore())?.pending || null;
    } catch (e) {
      error = formatApiError(e);
    }
  });

  async function download() {
    downloading = true;
    error = null;
    notice = null;
    try {
      const { blob, filename } = await api.downloadBackup(includeLogs);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      notice = `Backup saved as ${filename}.`;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      downloading = false;
    }
  }

  async function restore() {
    if (!file) return;
    if (!confirm('Restore this backup? When the server next restarts, everything (zones, settings, users, certificates) goes back to how it was in the backup.')) return;
    restoring = true;
    error = null;
    notice = null;
    try {
      pending = (await api.stageRestore(file))?.pending || null;
      notice = 'Backup checked and ready. Restart Daygle DNS to finish restoring it.';
      file = null;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      restoring = false;
    }
  }

  async function cancel() {
    error = null;
    notice = null;
    try {
      await api.cancelRestore();
      pending = null;
      notice = 'Restore cancelled. Nothing was changed.';
    } catch (e) {
      error = formatApiError(e);
    }
  }

  function contents(info) {
    const parts = [
      [info.zones, 'zone'],
      [info.records, 'record'],
      [info.users, 'user'],
      [info.certificates, 'certificate'],
      [info.ai_overrides, 'AI override'],
      [info.query_logs, 'query log entry', 'query log entries'],
    ];
    return parts
      .filter(([n]) => n > 0)
      .map(([n, one, many]) => `${n.toLocaleString()} ${n === 1 ? one : many || `${one}s`}`)
      .join(', ') || 'nothing';
  }
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if pending}
  <div class="card pending" style="margin-bottom: 14px">
    <h3 style="margin: 0 0 6px">Restore Waiting for a Restart</h3>
    <p style="margin: 0 0 10px">
      A backup from <strong>{formatDateTime(new Date(pending.created_at * 1000))}</strong>
      ({contents(pending)}) replaces the current data when Daygle DNS next starts.
      Restart it to finish, for example with <code>sudo systemctl restart daygle-dns</code>.
      The current database is kept beside the new one in case you need it back.
    </p>
    <button class="secondary" onclick={cancel}>Cancel Restore</button>
  </div>
{/if}

<div class="card" style="margin-bottom: 14px">
  <h3 style="margin: 0 0 10px">Back Up</h3>
  <div class="row">
    <label class="check"><input type="checkbox" bind:checked={includeLogs} /> <span>Include Query Logs</span></label>
    <button onclick={download} disabled={downloading}>{downloading ? 'Preparing…' : 'Download Backup'}</button>
  </div>
  <p class="muted help">
    One file with everything this server keeps: zones and records, DNSSEC keys,
    settings, console users, certificates, filtering and AI scanner overrides.
    Query logs are left out unless you include them, as they can be large. The
    file holds private keys and password hashes, so store it somewhere safe.
    From the command line: <code>daygle-dns backup FILE</code>.
  </p>
</div>

<div class="card">
  <h3 style="margin: 0 0 10px">Restore</h3>
  <div class="row">
    <input type="file" accept=".db,application/vnd.sqlite3,application/octet-stream" onchange={(e) => (file = e.currentTarget.files?.[0] || null)} />
    <button class="danger" onclick={restore} disabled={!file || restoring}>{restoring ? 'Checking…' : 'Restore Backup'}</button>
  </div>
  <p class="muted help">
    The backup is checked first, then applied when Daygle DNS next restarts, so
    nothing changes while it is running and you can still cancel. Everything goes
    back to how it was in the backup, including users and passwords. The current
    data is kept beside it as <code>&lt;database&gt;.before-restore-&lt;time&gt;</code>.
    From the command line: <code>daygle-dns restore FILE</code>, then restart.
  </p>
</div>

<style>
  .row { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 20px; }
  .row input[type='file'] { flex: 1 1 260px; min-width: 0; }
  .pending { border-color: #f5b041; }
  .check { display: flex; align-items: center; gap: 8px; }
</style>

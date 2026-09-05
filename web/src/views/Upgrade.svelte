<script>
  import { api, formatApiError } from '../api.js';

  let info = $state(null);
  let error = $state(null);
  let busy = $state(false);
  let copied = $state(false);

  async function load() {
    busy = true;
    error = null;
    try {
      info = await api.upgradeInfo();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => { load(); });

  async function copyCommand() {
    if (!info) return;
    try {
      await navigator.clipboard.writeText(info.upgrade_command);
      copied = true;
      setTimeout(() => { copied = false; }, 2000);
    } catch (e) {
      error = formatApiError(e);
    }
  }
</script><h1>Upgrade</h1>

<p class="muted" style="max-width: 75ch">
  The recommended way to update all components is the project's one-line installer,
  the same script used for fresh installs and upgrades. It fetches the latest source,
  rebuilds the server binary, installs it in place, and preserves your configuration,
  zones, certificates, and database.
</p >

{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if info}
  <div class="card" style="margin-bottom: 14px">
    <h3 style="margin-top: 0">Current Installation</h3>
    <div class="form-grid">
      <label><span>Installed Version</span><code>{info.version}</code></label>
      <label><span>Config File</span>{info.has_config_file ? 'Detected' : 'Not detected'}</label>
      <label><span>Service Manager</span>{info.has_systemd ? 'systemd' : 'Not detected'}</label>
    </div>
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
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 0.78rem; font-weight: 600; }
  td:first-child { width: 52%; }
</style>

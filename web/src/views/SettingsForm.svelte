<script>
  // The frame of a settings form that is saved on its own (a "Settings" tab
  // on a feature page): the success/error notices, a sticky save bar
  // (Save, Discard/Reload, Reset to Defaults) and the form styles shared
  // with the Settings page. The form fields are the children.
  let {
    loaded = false,
    dirty = false,
    busy = false,
    notice = null,
    error = null,
    onSave,
    onReload,
    onReset = null,
    children,
  } = $props();
</script>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

{#if loaded}
  <div class="actions">
    <button onclick={onSave} disabled={busy || !dirty}>{busy ? 'Saving...' : 'Save Changes'}</button>
    <button class="secondary" onclick={onReload} disabled={busy}>{dirty ? 'Discard Changes' : 'Reload'}</button>
    {#if onReset}<button class="secondary" onclick={onReset} disabled={busy}>Reset to Defaults</button>{/if}
    {#if dirty}<span class="unsaved">Unsaved changes</span>{/if}
  </div>
  <div class="settings-form">
    {@render children()}
  </div>
{:else if !error}
  <div class="card"><p class="muted">Loading...</p></div>
{/if}

<style>
  /* Save bar: stays in view while scrolling a long form. */
  .actions {
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
    position: sticky;
    top: 0;
    z-index: 5;
    align-items: center;
    padding: 10px 0;
    background: var(--bg);
  }
  .unsaved { color: var(--warn); font-size: 0.85rem; }
  .settings-form :global(.stacked) { display: flex; flex-direction: column; gap: 4px; margin-bottom: 4px; }
  .settings-form :global(.form-grid) {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
    align-items: end;
  }
  .settings-form :global(.form-grid.top) { align-items: start; }
  .settings-form :global(.recursive-cache-grid) {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    align-items: start;
  }
  /* Two lines for every label, so the inputs line up whether or not a
     label wraps. */
  .settings-form :global(.recursive-cache-grid label:not(.check) > span:first-child) { min-height: 2.6em; display: flex; align-items: flex-end; }
  .settings-form :global(.recursive-cache-grid label.check) { padding-top: 2.6em; }
  .settings-form :global(label) { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  .settings-form :global(label span) { color: var(--muted); }
  .settings-form :global(label.check) { flex-direction: row; align-items: center; gap: 8px; padding-bottom: 8px; }
  .settings-form :global(label.check span) { color: var(--text); }
  .settings-form :global(h4) { margin: 14px 0 8px; }
  .settings-form :global(.help.restart) { color: var(--warn); margin-top: 8px; }
</style>

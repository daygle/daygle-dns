<script>
  import { hiddenColumns, isHidden, loadColumns, setHidden } from './columns.svelte.js';

  // A "Columns" menu for a data table: tick the columns to show. `table`
  // names the table (the choice is remembered per table); `columns` are
  // { key, label, locked } - a locked column is always shown.
  let { table, columns } = $props();

  let open = $state(false);
  let root;

  const hidden = $derived((hiddenColumns.map[table] || []).filter((k) => columns.some((c) => c.key === k)));

  $effect(() => {
    loadColumns();
  });

  function toggle(key) {
    const next = isHidden(table, key) ? hidden.filter((k) => k !== key) : [...hidden, key];
    setHidden(table, next);
  }

  function onWindowClick(e) {
    if (open && root && !root.contains(e.target)) open = false;
  }

  function onKeydown(e) {
    if (open && e.key === 'Escape') open = false;
  }
</script>

<svelte:window onclick={onWindowClick} onkeydown={onKeydown} />

<div class="picker" bind:this={root}>
  <button
    type="button"
    class="secondary"
    aria-haspopup="true"
    aria-expanded={open}
    onclick={() => (open = !open)}
    title="Choose the columns this table shows"
  >
    Columns{#if hidden.length} ({columns.length - hidden.length}/{columns.length}){/if}
  </button>
  {#if open}
    <div class="menu" role="group" aria-label="Columns">
      {#each columns as c (c.key)}
        <label class:locked={c.locked}>
          <input
            type="checkbox"
            checked={c.locked || !isHidden(table, c.key)}
            disabled={c.locked}
            onchange={() => toggle(c.key)}
          />
          <span>{c.label}</span>
        </label>
      {/each}
      <div class="foot">
        <button type="button" class="link" onclick={() => setHidden(table, [])} disabled={!hidden.length}>Show All</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .picker { position: relative; display: inline-block; }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 20;
    min-width: 190px;
    padding: 8px 0;
    background: var(--panel, var(--bg));
    border: 1px solid var(--border);
    border-radius: 10px;
    box-shadow: 0 8px 24px rgb(0 0 0 / 0.35);
  }
  label {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 14px;
    font-size: 0.85rem;
    color: var(--text);
    cursor: pointer;
    white-space: nowrap;
  }
  label:hover { background: color-mix(in srgb, var(--accent) 10%, transparent); }
  label.locked { color: var(--muted); cursor: default; }
  label input { width: auto; margin: 0; }
  .foot { border-top: 1px solid var(--border); margin-top: 6px; padding: 6px 14px 0; }
  .link { background: none; border: none; padding: 0; color: var(--accent); cursor: pointer; font-size: 0.82rem; }
  .link:disabled { color: var(--muted); cursor: default; }
</style>

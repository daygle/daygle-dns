<script>
  import { actionIcons } from './icons.svelte.js';

  // A small table-row action button that shows an icon instead of a word.
  // `label` is the tooltip and the name read out by screen readers.
  let { icon, label, variant = 'secondary', onclick, disabled = false } = $props();
</script>

<button type="button" class="icon-button {variant}" {onclick} {disabled} title={label} aria-label={label}>
  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d={actionIcons[icon]} />
  </svg>
</button>

<style>
  .icon-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 6px 8px;
    line-height: 0;
  }
</style>

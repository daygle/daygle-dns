<script>
  import { actionIcons } from './icons.svelte.js';

  // A small table-row action button that shows an icon instead of a word.
  // `label` is the name read out by screen readers and, unless `title`
  // says something else (such as why the button is disabled), the tooltip.
  let { icon, label, title = label, variant = 'secondary', onclick, disabled = false } = $props();
</script>

<button type="button" class="icon-button {variant}" {onclick} {disabled} {title} aria-label={label}>
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

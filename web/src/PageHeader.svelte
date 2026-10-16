<script>
  import { sidebar } from './nav.svelte.js';
  import { icons } from './icons.svelte.js';

  let { icon, title, lead, tagline } = $props();
  let showSidebarIcon = $derived(!icon && sidebar.open !== undefined);
</script>

<div class="hero card">
  <span class="hero-mark">
    {#if icon}
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d={icon} />
      </svg>
    {:else if showSidebarIcon}
      <svg
        class="sidebar-icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d={sidebar.open ? icons.sidebarCollapse : icons.sidebarExpand} />
      </svg>
    {/if}
  </span>

  <div>
    <h1>{title}</h1>
    {#if lead}
      {#if typeof lead === 'function'}
        <div class="lead">{@render lead()}</div>
      {:else}
        <p class="lead">{lead}</p>
      {/if}
    {/if}
    {#if tagline}
      {#if typeof tagline === 'function'}
        <p class="muted">{@render tagline()}</p>
      {:else}
        <p class="muted">{tagline}</p>
      {/if}
    {/if}
  </div>
</div>

<style>
  .hero {
    display: flex;
    gap: 16px;
    align-items: center;
    margin-bottom: 18px;
  }
  .hero-mark {
    flex: 0 0 auto;
    width: 52px;
    height: 52px;
    border-radius: 12px;
    background: rgba(91, 140, 255, 0.14);
    color: var(--accent);
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .hero-mark svg {
    width: 28px;
    height: 28px;
  }
  .hero-mark .sidebar-icon {
    display: block;
  }
  .hero h1 {
    margin: 0;
    font-size: clamp(1.25rem, 1rem + 1vw, 1.55rem);
    line-height: 1.2;
  }
  .lead {
    font-size: 1.02rem;
    line-height: 1.5;
    margin: 6px 0 0;
  }
  .hero .muted {
    margin: 4px 0 0;
    font-size: 0.9rem;
    line-height: 1.5;
  }
</style>
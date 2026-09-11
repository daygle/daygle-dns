<script>
  let { icon, title, lead, tagline } = $props();
</script>

<div class="hero card">
  <span class="hero-mark">
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
    margin-bottom: 16px;
  }
  .hero-mark {
    color: var(--accent);
    flex: 0 0 auto;
    display: inline-flex;
  }
  .hero-mark svg {
    width: 34px;
    height: 34px;
  }
  .hero h1 {
    margin: 0 0 6px;
    font-size: 1.45rem;
  }
  .lead {
    font-size: 1.05rem;
    margin: 0 0 4px;
    max-width: 76ch;
  }
  .hero .muted {
    margin: 0;
    max-width: 76ch;
  }
</style>
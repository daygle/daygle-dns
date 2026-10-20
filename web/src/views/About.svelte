<script>
  import { api } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';

  let status = $state(null);
  let error = $state(null);

  async function loadStatus() {
    try {
      status = await api.status();
    } catch (e) {
      error = String(e.message || e);
    }
  }

  $effect(() => {
    loadStatus();
  });

  const features = [
    {
      icon: icons.zones,
      title: 'Authoritative DNS',
      text: 'SQLite-backed zones, records, zone transfers, DNSSEC signing, and dynamic updates.',
    },
    {
      icon: icons.cache,
      title: 'Recursive Resolution',
      text: 'Caching, DNSSEC validation, retries, conditional forwarding, prefetch, and serve-stale support.',
    },
    {
      icon: icons.filtering,
      title: 'Policy Controls',
      text: 'Trusted domains, blocked domains, remote blocklist sources, client rules, and split horizon DNS.',
    },
    {
      icon: icons.certificates,
      title: 'Modern Protocols',
      text: 'DNS over TLS, DNS over HTTPS, and DNS over QUIC with a built-in management console.',
    },
  ];
</script>

<PageHeader
  icon={icons.about}
  title="Daygle DNS"
  lead="A modern, secure, and manageable DNS server for homes, labs, and networks."
  tagline="Designed to combine authoritative DNS, recursive resolution, filtering, caching, and a practical web console in one service."
/>

<div class="feature-grid">
  {#each features as feature (feature.title)}
    <div class="card feature">
      <!-- Same line icons as the sidebar. -->
      <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d={feature.icon} />
      </svg>
      <div>
        <h3>{feature.title}</h3>
        <p class="muted">{feature.text}</p>
      </div>
    </div>
  {/each}
</div>

<div class="details-grid">
  <div class="card">
    <h3 style="margin: 0 0 10px">Application Details</h3>
    <table>
      <tbody>
        <tr><td class="muted">Version</td><td>{#if status?.version}<code>v{status.version}</code>{:else if error}<span class="muted">Unavailable</span>{:else}<span class="muted">Loading…</span>{/if}</td></tr>
        <tr><td class="muted">License</td><td>Apache License 2.0</td></tr>
        <tr><td class="muted">Authoritative Storage</td><td>SQLite</td></tr>
        <tr><td class="muted">DNS Engine</td><td>Hickory DNS</td></tr>
        <tr><td class="muted">Web Console</td><td>Svelte</td></tr>
        <tr><td class="muted">Implementation</td><td>Rust</td></tr>
      </tbody>
    </table>
  </div>

</div>

<div class="card footer-card">
  <p class="muted">Daygle DNS is open-source software built for clear visibility and dependable DNS operations.</p>
  <a href="https://github.com/daygle/daygle-dns" target="_blank" rel="noreferrer">View the project on GitHub ↗</a>
</div>

<style>
  h2, h3 { margin-top: 0; }
  .feature-grid, .details-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
  /* Four features: one row on wide screens, 2 x 2 below that, never 3 + 1. */
  .feature-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 14px; }
  @media (max-width: 1180px) { .feature-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 600px) { .feature-grid { grid-template-columns: 1fr; } }
  .feature { display: flex; gap: 14px; }
  .feature h3 { margin-bottom: 6px; font-size: 1rem; }
  .feature p { margin: 0; line-height: 1.45; }
  .feature-icon { color: var(--accent); width: 24px; height: 24px; flex: 0 0 24px; margin-top: 2px; }
  td:first-child { width: 52%; }
  .footer-card { margin-top: 14px; display: flex; justify-content: space-between; gap: 16px; align-items: center; flex-wrap: wrap; }
  .footer-card p { margin: 0; }
  a { color: var(--accent); }
</style>

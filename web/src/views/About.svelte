<script>
  import { api, formatApiError } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';

  let status = $state(null);
  let error = $state(null);

  async function loadStatus() {
    try {
      status = await api.status();
    } catch (e) {
      error = formatApiError(e);
    }
  }

  $effect(() => {
    loadStatus();
  });

  const features = [
    {
      icon: icons.zones,
      title: 'Authoritative DNS',
      text: 'Primary and secondary zones, DNSSEC signing, zone transfers, NOTIFY, dynamic updates and split horizon.',
    },
    {
      icon: icons.cache,
      title: 'Recursive Resolution',
      text: 'Resolve from the root servers or forward to upstreams, with DNSSEC validation, a verified local root zone, prefetch and serve-stale.',
    },
    {
      icon: icons.filtering,
      title: 'Filtering and Policies',
      text: 'Blocklists, allow and block lists, filtering groups, and per-client resolution policies.',
    },
    {
      icon: icons.ai,
      title: 'AI Safety Scanner',
      text: 'Classifies the domains in your traffic in the background and can block unsafe ones.',
    },
    {
      icon: icons.certificates,
      title: 'Encrypted DNS',
      text: 'DNS over TLS, HTTPS and QUIC, with opportunistic encryption towards nameservers.',
    },
    {
      icon: icons.logs,
      title: 'Visibility',
      text: 'Live dashboards, a searchable query log, and a web console with read-only accounts.',
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
        <tr><td class="muted">Version</td><td>{#if status?.version}<code>v{status.version}</code>{:else if error}<span class="muted">Unavailable</span>{:else}<span class="muted">Loading...</span>{/if}</td></tr>
        <tr><td class="muted">License</td><td>Apache License 2.0</td></tr>
        <tr><td class="muted">Built With</td><td>Rust, Hickory DNS, SQLite and Svelte</td></tr>
      </tbody>
    </table>
  </div>

</div>

<div class="card footer-card">
  <p class="muted">Daygle DNS is open-source software built for clear visibility and dependable DNS operations.</p>
  <a href="https://github.com/daygle/daygle-dns" target="_blank" rel="noreferrer">View the project on GitHub ↗</a>
</div>

<style>
  h3 { margin-top: 0; }
  .feature-grid, .details-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
  /* Six features: 3 x 2 on wide screens, 2 x 3 below that - never a lone card. */
  .feature-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); margin-bottom: 14px; }
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

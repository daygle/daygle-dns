<script>
  import { api } from '../api.js';

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
      icon: '◆',
      title: 'Authoritative DNS',
      text: 'SQLite-backed zones, records, zone transfers, DNSSEC signing, and dynamic updates.',
    },
    {
      icon: '◌',
      title: 'Recursive resolution',
      text: 'Caching, DNSSEC validation, retries, conditional forwarding, prefetch, and serve-stale support.',
    },
    {
      icon: '◈',
      title: 'Policy controls',
      text: 'Trusted domains, blocked domains, remote blocklist sources, client rules, and split horizon DNS.',
    },
    {
      icon: '◇',
      title: 'Modern protocols',
      text: 'DNS over TLS, DNS over HTTPS, and DNS over QUIC with a built-in management console.',
    },
  ];
</script>

<h1>About Daygle DNS</h1>

<div class="hero card">
  <div class="hero-mark">⬡</div>
  <div>
    <h2>Daygle DNS</h2>
    <p class="lead">A modern, secure, and manageable DNS server for homes, labs, and networks.</p>
    <p class="muted">Designed to combine authoritative DNS, recursive resolution, filtering, caching, and a practical web console in one service.</p>
  </div>
</div>

<div class="feature-grid">
  {#each features as feature (feature.title)}
    <div class="card feature">
      <div class="feature-icon">{feature.icon}</div>
      <div>
        <h3>{feature.title}</h3>
        <p class="muted">{feature.text}</p>
      </div>
    </div>
  {/each}
</div>

<div class="details-grid">
  <div class="card">
    <h3>Project details</h3>
    <table>
      <tbody>
        <tr><td class="muted">Version</td><td><code>{status?.version || 'Loading…'}</code></td></tr>
        <tr><td class="muted">License</td><td>Apache License 2.0</td></tr>
        <tr><td class="muted">Authoritative storage</td><td>SQLite</td></tr>
        <tr><td class="muted">DNS engine</td><td>Hickory DNS</td></tr>
        <tr><td class="muted">Web console</td><td>Svelte</td></tr>
        <tr><td class="muted">Implementation</td><td>Rust</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Runtime status</h3>
    {#if status}
      <table>
        <tbody>
          <tr><td class="muted">Uptime</td><td>{status.uptime_secs}s</td></tr>
          <tr><td class="muted">Zones</td><td>{status.zones}</td></tr>
          <tr><td class="muted">Records</td><td>{status.records}</td></tr>
          <tr><td class="muted">Recursive resolver</td><td>{status.recursion ? 'Enabled' : 'Disabled'}</td></tr>
          <tr><td class="muted">DNSSEC validation</td><td>{status.dnssec ? 'Enabled' : 'Disabled'}</td></tr>
        </tbody>
      </table>
    {:else if error}
      <p class="muted">Runtime details are unavailable: {error}</p>
    {:else}
      <p class="muted">Loading runtime details…</p>
    {/if}
  </div>
</div>

<div class="card footer-card">
  <p class="muted">Daygle DNS is open-source software built for clear visibility and dependable DNS operations.</p>
  <a href="https://github.com/daygle/daygle-dns" target="_blank" rel="noreferrer">View the project on GitHub ↗</a>
</div>

<style>
  h2, h3 { margin-top: 0; }
  .hero { display: flex; gap: 20px; align-items: center; margin-bottom: 16px; }
  .hero-mark { color: var(--accent); font-size: 3.2rem; line-height: 1; }
  .hero h2 { margin-bottom: 6px; }
  .lead { font-size: 1.05rem; margin: 0 0 8px; }
  .hero p { max-width: 760px; }
  .feature-grid, .details-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }
  .feature-grid { margin-bottom: 16px; }
  .feature { display: flex; gap: 14px; }
  .feature h3 { margin-bottom: 6px; font-size: 1rem; }
  .feature p { margin: 0; line-height: 1.45; }
  .feature-icon { color: var(--accent); font-size: 1.5rem; width: 28px; flex: 0 0 28px; }
  td { vertical-align: top; }
  td:first-child { width: 52%; }
  .footer-card { margin-top: 16px; display: flex; justify-content: space-between; gap: 16px; align-items: center; flex-wrap: wrap; }
  .footer-card p { margin: 0; }
  a { color: var(--accent); }
  @media (max-width: 560px) {
    .hero { align-items: flex-start; }
    .hero-mark { font-size: 2.4rem; }
  }
</style>

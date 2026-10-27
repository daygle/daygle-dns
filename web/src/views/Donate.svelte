<script>
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';

  // GitHub Sponsors profile for the project's owner (repo: daygle/daygle-dns).
  const sponsorUrl = 'https://github.com/sponsors/daygle';
  const repoUrl = 'https://github.com/daygle/daygle-dns';

  const funds = [
    {
      icon: icons.update,
      title: 'Maintenance',
      text: 'Dependency updates, security response and keeping pace with DNS standards.',
    },
    {
      icon: icons.ai,
      title: 'New Features',
      text: 'Console improvements and new server capabilities, like the AI scanner and encrypted DNS listeners.',
    },
    {
      icon: icons.certificates,
      title: 'Testing and Reliability',
      text: 'The integration test suite, release builds and the infrastructure behind them.',
    },
  ];
</script>

<PageHeader
  icon={icons.heart}
  title="Support Daygle DNS"
  lead="Daygle DNS is free and open-source software. If it serves you well, a sponsorship keeps its development going."
  tagline="One-time and monthly contributions are handled by GitHub Sponsors."
/>

<div class="card support-card">
  <div>
    <h3 style="margin: 0 0 6px">Sponsor on GitHub</h3>
    <p class="muted" style="margin: 0">
      Your support pays for maintenance, testing and new features. Every level helps, and you can
      cancel a monthly sponsorship at any time.
    </p>
  </div>
  <a class="sponsor-btn" href={sponsorUrl} target="_blank" rel="noreferrer">
    Become a Sponsor&nbsp;↗
  </a>
</div>

<div class="feature-grid">
  {#each funds as item (item.title)}
    <div class="card feature">
      <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d={item.icon} />
      </svg>
      <div>
        <h3>{item.title}</h3>
        <p class="muted">{item.text}</p>
      </div>
    </div>
  {/each}
</div>

<div class="card footer-card">
  <p class="muted">
    Not ready to sponsor? Starring the repository, reporting issues or sending improvements all
    help too.
  </p>
  <a href={repoUrl} target="_blank" rel="noreferrer">View the project on GitHub ↗</a>
</div>

<style>
  .support-card {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 18px;
    margin-bottom: 14px;
    flex-wrap: wrap;
  }
  .sponsor-btn {
    flex: 0 0 auto;
    background: var(--accent);
    color: #fff;
    font-weight: 600;
    border-radius: 6px;
    padding: 9px 16px;
    text-decoration: none;
    white-space: nowrap;
  }
  .feature-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    margin-bottom: 14px;
  }
  @media (max-width: 1180px) { .feature-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 600px) { .feature-grid { grid-template-columns: 1fr; } }
  .feature { display: flex; gap: 14px; }
  .feature h3 { margin: 0 0 6px; font-size: 1rem; }
  .feature p { margin: 0; line-height: 1.45; }
  .feature-icon { color: var(--accent); width: 24px; height: 24px; flex: 0 0 24px; margin-top: 2px; }
  .footer-card { display: flex; justify-content: space-between; gap: 16px; align-items: center; flex-wrap: wrap; }
  .footer-card p { margin: 0; }
  a { color: var(--accent); }
</style>

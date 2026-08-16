<script>
  import Status from './views/Status.svelte';
  import Zones from './views/Zones.svelte';
  import SplitHorizon from './views/SplitHorizon.svelte';
  import Logs from './views/Logs.svelte';
  import Blocklists from './views/Blocklists.svelte';
  import Settings from './views/Settings.svelte';

  let view = $state('status');

  const tabs = [
    { id: 'status', label: 'Status' },
    { id: 'zones', label: 'Zones & Records' },
    { id: 'split-horizon', label: 'Split Horizon' },
    { id: 'blocklists', label: 'Blocklists' },
    { id: 'logs', label: 'Logs' },
    { id: 'settings', label: 'Settings' },
  ];
</script>

<div class="shell">
  <aside>
    <div class="brand">
      <span class="logo">⬡</span>
      <div>
        <strong>Daygle DNS</strong>
        <div class="muted" style="font-size:0.75rem">Modern DNS server</div>
      </div>
    </div>
    <nav>
      {#each tabs as tab (tab.id)}
        <button
          class="nav-btn"
          class:active={view === tab.id}
          onclick={() => (view = tab.id)}
        >
          {tab.label}
        </button>
      {/each}
    </nav>
  </aside>

  <main>
    {#if view === 'status'}
      <Status />
    {:else if view === 'zones'}
      <Zones />
    {:else if view === 'split-horizon'}
      <SplitHorizon />
    {:else if view === 'blocklists'}
      <Blocklists />
    {:else if view === 'logs'}
      <Logs />
    {:else}
      <Settings />
    {/if}
  </main>
</div>

<style>
  .shell { display: flex; min-height: 100vh; }

  aside {
    width: 220px;
    background: var(--panel);
    border-right: 1px solid var(--border);
    padding: 20px 14px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    position: sticky;
    top: 0;
    height: 100vh;
  }

  .brand { display: flex; gap: 10px; align-items: center; }
  .logo { font-size: 1.6rem; color: var(--accent); }

  nav { display: flex; flex-direction: column; gap: 4px; }
  .nav-btn {
    background: none;
    color: var(--muted);
    text-align: left;
    border-radius: 6px;
    padding: 9px 12px;
  }
  .nav-btn:hover { background: var(--panel-2); color: var(--text); }
  .nav-btn.active { background: var(--accent); color: #fff; }

  main { flex: 1; padding: 24px 28px; max-width: 1100px; }
</style>
